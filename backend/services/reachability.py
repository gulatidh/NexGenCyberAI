"""Runtime-reachability multiplier for RPS scoring.

Two sources are supported, picked in order of preference:

  1. Wiz Issues GraphQL API
     Env: WIZ_API_TOKEN, WIZ_TENANT_URL (e.g. https://api.us1.app.wiz.io/graphql)
     We query Wiz for the finding's CVE and inspect issue/vulnerability fields
     that flag whether the affected asset is internet-exposed or has a
     known attack path. Wiz's `hasExposureToPublic` / `attackPath` signals
     map directly to a runtime reachability multiplier.

  2. CrowdStrike Falcon Spotlight
     Env: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_BASE_URL
          (default https://api.crowdstrike.com)
     Spotlight returns a vulnerability's `exposure_status` and
     `exposed_to_internet` flags per host.

If neither is configured we return `unknown` so RPS doesn't penalise
findings for missing telemetry — the verdict UI shows the gap and
points the user at the integration.

We never make network calls for individual findings on the hot path —
results are cached in-process for a short TTL keyed by (provider, cve).
"""
from __future__ import annotations
import logging
import os
import threading
import time
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 600  # 10 minutes
_cache: Dict[str, Dict[str, Any]] = {}
_cache_lock = threading.RLock()

# Token cache for CrowdStrike (1-hour token, refresh on expiry).
_falcon_token: Optional[Dict[str, Any]] = None


def _provider_enabled() -> str:
    """Pick the first configured provider — Wiz first."""
    if os.environ.get("WIZ_API_TOKEN") and os.environ.get("WIZ_TENANT_URL"):
        return "wiz"
    if os.environ.get("FALCON_CLIENT_ID") and os.environ.get("FALCON_CLIENT_SECRET"):
        return "falcon"
    return ""


def get_reachability(cve_id: Optional[str], resource_id: Optional[str] = None) -> Dict[str, Any]:
    """Return {value, source, provider, rationale}. source ∈ evidenced|unknown.

    Multiplier semantics:
        2.0  internet-exposed or active attack path
        1.5  reachable from untrusted internal segment
        1.0  reachable in private network
        0.5  isolated / not reachable
        unknown → 1.0 (no penalty)
    """
    provider = _provider_enabled()
    if not provider:
        return {
            "value": 1.0,
            "source": "unknown",
            "provider": None,
            "rationale": (
                "No Wiz or CrowdStrike Spotlight integration configured. "
                "Set WIZ_API_TOKEN+WIZ_TENANT_URL or FALCON_CLIENT_ID+FALCON_CLIENT_SECRET "
                "to evidence the reachability factor."
            ),
        }
    if not cve_id:
        return _no_evidence_response(provider, "Finding has no CVE — runtime lookup needs one.")

    cache_key = f"{provider}:{cve_id.upper()}:{resource_id or ''}"
    with _cache_lock:
        cached = _cache.get(cache_key)
        if cached and (time.time() - cached["_ts"] < _CACHE_TTL_SECONDS):
            return {k: v for k, v in cached.items() if k != "_ts"}

    try:
        if provider == "wiz":
            out = _wiz_reachability(cve_id, resource_id)
        else:
            out = _falcon_reachability(cve_id, resource_id)
    except Exception as exc:
        logger.exception("Reachability lookup failed for %s via %s", cve_id, provider)
        out = _no_evidence_response(provider, f"Provider call failed: {exc}")

    with _cache_lock:
        _cache[cache_key] = {**out, "_ts": time.time()}
    return out


def _no_evidence_response(provider: Optional[str], rationale: str) -> Dict[str, Any]:
    return {
        "value": 1.0,
        "source": "unknown",
        "provider": provider,
        "rationale": rationale,
    }


# ── Wiz ──────────────────────────────────────────────────────────────────────


_WIZ_QUERY = """
query findVulnerabilitiesByCVE($filter: VulnerabilityFindingFilters) {
  vulnerabilityFindings(first: 5, filterBy: $filter) {
    nodes {
      id
      severity
      hasExploit
      hasCisaKevExploit
      validatedInTheWild
      vulnerableAsset {
        ... on VulnerableAssetBase {
          providerUniqueId
          hasExposureToPublic
        }
      }
    }
  }
}
"""


def _wiz_reachability(cve_id: str, resource_id: Optional[str]) -> Dict[str, Any]:
    """Wiz Issues GraphQL — hasExposureToPublic + validatedInTheWild signals."""
    url = os.environ["WIZ_TENANT_URL"]
    token = os.environ["WIZ_API_TOKEN"]
    payload = {
        "query": _WIZ_QUERY,
        "variables": {"filter": {"cve": [cve_id.upper()]}},
    }
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    nodes = (((data or {}).get("data") or {}).get("vulnerabilityFindings") or {}).get("nodes") or []
    if not nodes:
        return _no_evidence_response(
            "wiz",
            f"Wiz returned no vulnerability findings for {cve_id}. Asset may not be inventoried in Wiz.",
        )
    # Pick the worst-case across matching findings.
    exposed_public = False
    validated_itw = False
    for n in nodes:
        if n.get("validatedInTheWild") or n.get("hasCisaKevExploit"):
            validated_itw = True
        asset = n.get("vulnerableAsset") or {}
        if asset.get("hasExposureToPublic"):
            exposed_public = True
    if exposed_public and validated_itw:
        return {"value": 2.0, "source": "evidenced", "provider": "wiz",
                "rationale": "Wiz: vulnerable asset has public exposure AND exploit is validated in the wild (CISA KEV / Wiz signal)."}
    if exposed_public:
        return {"value": 2.0, "source": "evidenced", "provider": "wiz",
                "rationale": "Wiz: vulnerable asset is internet-exposed."}
    if validated_itw:
        return {"value": 1.5, "source": "evidenced", "provider": "wiz",
                "rationale": "Wiz: exploit validated in the wild; asset not directly exposed."}
    return {"value": 1.0, "source": "evidenced", "provider": "wiz",
            "rationale": "Wiz: asset reachable on private network; no public exposure or validated exploit signal."}


# ── CrowdStrike Falcon Spotlight ────────────────────────────────────────────


def _falcon_token_value() -> str:
    """Return a valid OAuth2 client-credentials token. Cached for ~55 min."""
    global _falcon_token
    if _falcon_token and time.time() < _falcon_token["expires_at"] - 60:
        return _falcon_token["token"]
    base = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")
    cid = os.environ["FALCON_CLIENT_ID"]
    secret = os.environ["FALCON_CLIENT_SECRET"]
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(
            f"{base}/oauth2/token",
            data={"client_id": cid, "client_secret": secret},
        )
        resp.raise_for_status()
        body = resp.json()
    _falcon_token = {
        "token": body["access_token"],
        "expires_at": time.time() + int(body.get("expires_in", 1500)),
    }
    return _falcon_token["token"]


def _falcon_reachability(cve_id: str, resource_id: Optional[str]) -> Dict[str, Any]:
    """Falcon Spotlight — query combinedVulnerabilities by CVE id."""
    base = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")
    token = _falcon_token_value()
    filter_str = f"cve.id:'{cve_id.upper()}'"
    with httpx.Client(timeout=15.0) as client:
        resp = client.get(
            f"{base}/spotlight/combined/vulnerabilities/v1",
            params={"filter": filter_str, "limit": 10},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        data = resp.json()
    items = (data or {}).get("resources") or []
    if not items:
        return _no_evidence_response(
            "falcon",
            f"Falcon Spotlight returned no hosts with {cve_id}. CVE may not affect any inventoried host.",
        )
    exposed = False
    for it in items:
        for tag in (it.get("host_info") or {}).get("tags") or []:
            if "internet" in tag.lower() or "public" in tag.lower():
                exposed = True
        # Spotlight exposes 'exprt_rating' and 'exploitability_factors'
        if (it.get("exploitability_factors") or "").lower() in ("active", "actively_exploited"):
            exposed = True
    if exposed:
        return {"value": 2.0, "source": "evidenced", "provider": "falcon",
                "rationale": "CrowdStrike Spotlight: vulnerable host is internet-tagged or CVE is actively exploited."}
    return {"value": 1.0, "source": "evidenced", "provider": "falcon",
            "rationale": "CrowdStrike Spotlight: CVE present on internal hosts; no internet exposure tag."}
