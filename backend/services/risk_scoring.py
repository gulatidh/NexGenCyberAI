"""Centralised Likelihood × Impact risk scoring on a 1-10 scale.

    Risk = Likelihood × Impact / 10        (both factors 1-10 → score 0-10)

e.g. Likelihood 8 × Impact 9 = 72 / 10 = 7.2.

Likelihood and impact are deliberately derived from **different** signals so a
risk's two factors are not identical:

  * Impact      = worst-case consequence  → severity, CVSS, data sensitivity,
                  asset criticality.
  * Likelihood  = probability of exploitation → severity baseline, EPSS, KEV,
                  whether a CVE exists, and internet/exposure signals.

The severity baselines below are intentionally asymmetric (impact a notch above
likelihood) so even a finding with no extra signal still gets distinct L and I.
The derived risk_score stays on the familiar 0-10 band, so the Risk Register /
Risk Overview colour thresholds are unchanged.
"""
from __future__ import annotations
from typing import Optional, Tuple

SCALE_MAX = 10

# Severity → baseline IMPACT (worst-case consequence) on the 1-10 scale.
_IMPACT_BASE = {"critical": 9, "high": 7, "medium": 5, "low": 3, "info": 2}
# Severity → baseline LIKELIHOOD (exploitation probability), a notch lower —
# a finding's damage is rated by severity, but exploitation isn't guaranteed.
_LIKELIHOOD_BASE = {"critical": 6, "high": 4, "medium": 3, "low": 2, "info": 1}

# Back-compat: severity → (likelihood, impact) baseline pair.
SEV_TO_LI = {sev: (_LIKELIHOOD_BASE[sev], _IMPACT_BASE[sev]) for sev in _IMPACT_BASE}

# Signals scanned in a finding/risk's title + description + resource type.
_EXPOSURE_KW = (
    "internet", "public", "0.0.0.0", "unrestricted", "anonymous",
    "unauthenticated", "exposed", "world-readable", "any source",
    "publicly", "open to the internet", "no authentication",
)
_SHIELD_KW = ("internal", "private", "vpc-only", "restricted to", "not exposed")
_SENSITIVE_KW = (
    "pii", "phi", "secret", "credential", "password", "key vault", "private key",
    "database", "cardholder", "encryption", "encrypt", "owner permission",
    "privileged", "admin", "sensitive",
)


def _num(v) -> bool:
    try:
        return v is not None and float(v) > 0
    except (TypeError, ValueError):
        return False


def clamp_scale(value, default: int) -> int:
    """Coerce a value to an int in [1, 10]; return `default` if not numeric."""
    try:
        n = int(round(float(value)))
    except (TypeError, ValueError):
        return default
    return max(1, min(SCALE_MAX, n))


def compute_risk_score(likelihood, impact) -> float:
    """Risk = L × I / 10, rounded to 1 decimal (0-10)."""
    try:
        return round((int(likelihood) * int(impact)) / 10.0, 1)
    except (TypeError, ValueError):
        return 0.0


def sev_baseline(severity: Optional[str]) -> Tuple[int, int]:
    """Severity → (likelihood, impact) baseline on the 1-10 scale (asymmetric)."""
    sev = (severity or "medium").lower()
    return (_LIKELIHOOD_BASE.get(sev, 3), _IMPACT_BASE.get(sev, 5))


def from_finding(
    severity: Optional[str],
    *,
    cvss=None,
    epss=None,
    cve=None,
    kev: bool = False,
    text: str = "",
    asset_criticality: Optional[str] = None,
) -> Tuple[int, int, float]:
    """Derive distinct (likelihood, impact, risk_score) for a finding/risk.

    Impact tracks consequence (severity + CVSS + data sensitivity + asset
    criticality); likelihood tracks exploitability (severity + EPSS/KEV/CVE +
    internet exposure). Falls back to the asymmetric severity baseline so the
    two factors differ even with no extra signal."""
    sev = (severity or "medium").lower()
    likelihood = _LIKELIHOOD_BASE.get(sev, 3)
    impact = _IMPACT_BASE.get(sev, 5)
    t = (text or "").lower()

    # ── Impact: worst-case consequence ──
    if _num(cvss):
        impact = clamp_scale(round((impact + float(cvss)) / 2), impact)
    if any(k in t for k in _SENSITIVE_KW):
        impact = min(SCALE_MAX, impact + 1)
    if (asset_criticality or "").lower() in ("critical", "high"):
        impact = min(SCALE_MAX, impact + 1)

    # ── Likelihood: probability of exploitation ──
    if kev:
        likelihood = max(likelihood, 9)
    elif _num(epss):
        likelihood = clamp_scale(round(1 + float(epss) * 9), likelihood)
    elif cve:
        likelihood = min(SCALE_MAX, likelihood + 1)
    if any(k in t for k in _EXPOSURE_KW):
        likelihood = min(SCALE_MAX, likelihood + 2)
    elif any(k in t for k in _SHIELD_KW):
        likelihood = max(1, likelihood - 1)

    return likelihood, impact, compute_risk_score(likelihood, impact)
