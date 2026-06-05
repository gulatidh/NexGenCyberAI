"""Unified sync registry for admin-triggered, on-demand external feeds.

Single place to add a new feed:
    REGISTRY["feed_id"] = SyncFeed(
        id="feed_id",
        name="Display Name",
        category="threat_intel | cve | framework",
        description="One-sentence summary surfaced in the Sync page tile.",
        source_url="https://...",
        sync_fn=lambda: ...,    # callable returning dict with count + extras
        stats_fn=lambda: ...,    # callable returning dict with last_synced_at + count
    )

The public API the router uses:
    list_feeds() -> [{...feed metadata + stats}, ...]
    sync_feed(feed_id) -> {...result, errors: [...]}

Each feed persists its own last-sync timestamp + count via the underlying
service (threat_intel for EPSS/KEV, json files for NVD/frameworks etc.),
so a process restart doesn't lose state.
"""
from __future__ import annotations
import json
import logging
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

from core.paths import data_dir
# Persistent, worker-shared cache dir (/home/data on Azure). The old in-repo
# path made sync counts vanish on reload — each gunicorn worker had its own
# ephemeral copy of wwwroot. See core/paths.py.
_CACHE_DIR = data_dir()
_GENERIC_STATS_FILE = _CACHE_DIR / "sync_feed_stats.json"


# ── Generic per-feed state (NVD, frameworks etc.) ────────────────────────────


def _read_generic_stats() -> Dict[str, Any]:
    if not _GENERIC_STATS_FILE.exists():
        return {}
    try:
        return json.loads(_GENERIC_STATS_FILE.read_text())
    except Exception:
        return {}


def _write_generic_stats(stats: Dict[str, Any]) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _GENERIC_STATS_FILE.write_text(json.dumps(stats, default=str))
    except Exception:
        logger.exception("Failed to persist generic sync stats")


def _record_generic(feed_id: str, count: int, extra: Optional[Dict[str, Any]] = None) -> None:
    stats = _read_generic_stats()
    stats[feed_id] = {
        "count": count,
        "last_synced_at": datetime.now(timezone.utc).isoformat(),
        **(extra or {}),
    }
    _write_generic_stats(stats)


def _generic_stats(feed_id: str) -> Dict[str, Any]:
    rec = _read_generic_stats().get(feed_id) or {}
    return {
        "count": rec.get("count", 0),
        "last_synced_at": rec.get("last_synced_at"),
        **{k: v for k, v in rec.items() if k not in ("count", "last_synced_at")},
    }


# ── Feed implementations ─────────────────────────────────────────────────────


def _sync_epss() -> Dict[str, Any]:
    from services.threat_intel import _refresh_epss, _persist_to_disk
    count = _refresh_epss()
    _persist_to_disk()
    return {"count": count}


def _stats_epss() -> Dict[str, Any]:
    from services.threat_intel import stats as ti_stats
    s = ti_stats()
    return {"count": s.get("epss_count", 0), "last_synced_at": s.get("epss_fetched_at")}


def _sync_kev() -> Dict[str, Any]:
    from services.threat_intel import _refresh_kev, _persist_to_disk
    count = _refresh_kev()
    _persist_to_disk()
    return {"count": count}


def _stats_kev() -> Dict[str, Any]:
    from services.threat_intel import stats as ti_stats
    s = ti_stats()
    return {"count": s.get("kev_count", 0), "last_synced_at": s.get("kev_fetched_at")}


def _sync_nvd_recent() -> Dict[str, Any]:
    """Pull CVEs modified in the last 8 days from the NVD 2.0 REST API and
    cache CVE IDs + key metadata (CVSS / CWE / description) for finding
    enrichment. (The old 1.1 JSON data feeds were retired by NVD in Dec 2023,
    so this uses the 2.0 API — much faster with an NVD API key.)"""
    import time
    import httpx
    from datetime import datetime, timezone, timedelta
    from core.config import get_settings

    key = (get_settings().NVD_API_KEY or "").strip()
    headers = {"apiKey": key} if key else {}
    delay = 0.7 if key else 6.5  # NVD: 50 req/30s with a key, 5 without

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=8)
    fmt = "%Y-%m-%dT%H:%M:%S.000"  # NVD 2.0 ISO-8601 (UTC assumed)
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    cves: Dict[str, Dict[str, Any]] = {}
    start_index, total, page = 0, None, 0
    with httpx.Client(timeout=60.0, follow_redirects=True, headers=headers) as client:
        while page < 6:  # cap pages — the 8-day window is small
            params = {
                "lastModStartDate": start.strftime(fmt),
                "lastModEndDate": end.strftime(fmt),
                "resultsPerPage": 2000,
                "startIndex": start_index,
            }
            resp = client.get(base, params=params)
            if resp.status_code in (403, 429):
                time.sleep(delay * 3)
                resp = client.get(base, params=params)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", []) or []
            for v in vulns:
                cve = v.get("cve") or {}
                cid = (cve.get("id") or "").upper()
                if not cid:
                    continue
                desc = ""
                for d in cve.get("descriptions") or []:
                    if d.get("lang") == "en":
                        desc = d.get("value") or ""
                        break
                cvss = None
                metrics = cve.get("metrics") or {}
                for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    arr = metrics.get(mk) or []
                    if arr:
                        cvss = (arr[0].get("cvssData") or {}).get("baseScore")
                        if cvss is not None:
                            break
                cwes = []
                for w in cve.get("weaknesses") or []:
                    for d in w.get("description") or []:
                        val = d.get("value")
                        if val and val.startswith("CWE-"):
                            cwes.append(val)
                cves[cid] = {
                    "cvss_v3": cvss,
                    "cwes": cwes,
                    "description": desc[:500],
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                }
            total = data.get("totalResults", 0)
            start_index += data.get("resultsPerPage", 0) or 2000
            page += 1
            if start_index >= (total or 0):
                break
            time.sleep(delay)

    # Persist alongside the threat-intel cache so RPS enrichers can find it.
    cache_path = _CACHE_DIR / "nvd_cve_cache.json"
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        existing: Dict[str, Any] = {}
        if cache_path.exists():
            existing = json.loads(cache_path.read_text())
        existing.update(cves)
        cache_path.write_text(json.dumps(existing))
    except Exception:
        logger.exception("Failed to persist NVD cache")

    _record_generic("nvd_recent", len(cves), {"total_in_cache": len(existing) if cache_path.exists() else len(cves)})
    return {"count": len(cves)}


def _stats_nvd_recent() -> Dict[str, Any]:
    s = _generic_stats("nvd_recent")
    cache_path = _CACHE_DIR / "nvd_cve_cache.json"
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text())
            s["count"] = len(data)
        except Exception:
            pass
    return s


# ── MITRE ATT&CK + CAPEC threat-library sync ────────────────────────────────


_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
_CAPEC_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"


def _upsert_library(rows: List[Dict[str, Any]], source: str) -> int:
    """Bulk upsert into the threat_library table. Returns rows touched."""
    from db.database import SessionLocal
    from api.models.models import ThreatLibrary

    if not rows:
        return 0
    db = SessionLocal()
    touched = 0
    try:
        # Build a {source_id: row} map of existing entries for this source so
        # we update in-place instead of N round-trips.
        existing = {
            r.source_id: r
            for r in db.query(ThreatLibrary).filter(ThreatLibrary.source == source).all()
        }
        for row in rows:
            sid = row.get("source_id")
            if not sid:
                continue
            obj = existing.get(sid)
            if obj is None:
                obj = ThreatLibrary(source=source, source_id=sid)
                db.add(obj)
            obj.name = (row.get("name") or "")[:512]
            obj.description = row.get("description") or ""
            obj.category = row.get("category")
            obj.severity_default = row.get("severity_default")
            obj.mitigation_hint = row.get("mitigation_hint")
            obj.related_cwes = row.get("related_cwes") or []
            obj.extra = row.get("extra") or {}
            touched += 1
        db.commit()
    finally:
        db.close()
    return touched


def _sync_attack() -> Dict[str, Any]:
    """Download the MITRE ATT&CK enterprise STIX bundle, extract every
    attack-pattern object, and upsert into threat_library with
    source='attack'. Stores tactic (initial_access, execution, …) in
    `category` so the threat modeler can sample by tactic."""
    import httpx
    logger.info("Refreshing MITRE ATT&CK from %s", _ATTACK_URL)
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        resp = client.get(_ATTACK_URL)
        resp.raise_for_status()
        bundle = resp.json()
    rows: List[Dict[str, Any]] = []
    for obj in bundle.get("objects", []) or []:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        # Pull T-id from external_references
        tid = None
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
                break
        if not tid or not tid.startswith("T"):
            continue
        # Tactic from kill_chain_phases (mitre-attack)
        tactics = []
        for kc in obj.get("kill_chain_phases", []) or []:
            if kc.get("kill_chain_name") == "mitre-attack":
                tactics.append(kc.get("phase_name"))
        rows.append({
            "source_id": tid,
            "name": obj.get("name") or tid,
            "description": (obj.get("description") or "")[:4000],
            "category": tactics[0] if tactics else None,
            "severity_default": "high",  # ATT&CK techniques generally high-risk
            "mitigation_hint": None,
            "related_cwes": [],
            "extra": {
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms") or [],
                "data_sources": obj.get("x_mitre_data_sources") or [],
            },
        })
    n = _upsert_library(rows, source="attack")
    _record_generic("attack", n)
    return {"count": n}


def _stats_attack() -> Dict[str, Any]:
    from db.database import SessionLocal
    from api.models.models import ThreatLibrary
    n = 0
    db = SessionLocal()
    try:
        n = db.query(ThreatLibrary).filter(ThreatLibrary.source == "attack").count()
    except Exception:
        # Table doesn't exist yet (e.g. before create_all). Treat as 0.
        pass
    finally:
        db.close()
    s = _generic_stats("attack")
    s["count"] = n
    return s


# Mapping CAPEC top-level abstractions → STRIDE buckets. CAPEC doesn't
# ship a clean STRIDE mapping so we use heuristics from CAPEC's "scope"
# field if present, else leave category null.
_CAPEC_STRIDE_KEYS = {
    "spoofing": "spoofing",
    "integrity": "tampering",
    "non-repudiation": "repudiation",
    "non repudiation": "repudiation",
    "confidentiality": "information_disclosure",
    "availability": "denial_of_service",
    "authorization": "elevation_of_privilege",
    "authorisation": "elevation_of_privilege",
    "access control": "elevation_of_privilege",
}


def _capec_stride(obj: Dict[str, Any]) -> Optional[str]:
    """Best-effort STRIDE bucket from CAPEC's 'scope' or 'consequences'."""
    text_blobs: List[str] = []
    for c in obj.get("x_capec_consequences", {}).values() if isinstance(obj.get("x_capec_consequences"), dict) else []:
        if isinstance(c, list):
            text_blobs.extend(x for x in c if isinstance(x, str))
    text_blobs.append((obj.get("description") or "")[:200])
    haystack = " ".join(text_blobs).lower()
    for key, stride in _CAPEC_STRIDE_KEYS.items():
        if key in haystack:
            return stride
    return None


def _sync_capec() -> Dict[str, Any]:
    """Download the CAPEC STIX bundle (mitre/cti) and upsert as source='capec'."""
    import httpx
    logger.info("Refreshing CAPEC from %s", _CAPEC_URL)
    with httpx.Client(timeout=90.0, follow_redirects=True) as client:
        resp = client.get(_CAPEC_URL)
        resp.raise_for_status()
        bundle = resp.json()
    rows: List[Dict[str, Any]] = []
    for obj in bundle.get("objects", []) or []:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_capec_status") == "Deprecated":
            continue
        cid = None
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "capec":
                cid = ref.get("external_id")
                break
        if not cid or not cid.startswith("CAPEC-"):
            continue
        # Pull CWE refs
        cwes = [
            ref.get("external_id")
            for ref in (obj.get("external_references", []) or [])
            if ref.get("source_name") == "cwe" and ref.get("external_id")
        ]
        # Severity from x_capec_likelihood_of_attack + typical_severity if present
        sev_default = (obj.get("x_capec_typical_severity") or "").lower() or None
        rows.append({
            "source_id": cid,
            "name": obj.get("name") or cid,
            "description": (obj.get("description") or "")[:4000],
            "category": _capec_stride(obj),
            "severity_default": sev_default,
            "mitigation_hint": (obj.get("x_capec_skills_required") or {}).get("High")
                or (obj.get("x_capec_skills_required") or {}).get("Medium")
                or None,
            "related_cwes": cwes[:8],
            "extra": {
                "abstraction": obj.get("x_capec_abstraction"),
                "likelihood": obj.get("x_capec_likelihood_of_attack"),
            },
        })
    n = _upsert_library(rows, source="capec")
    _record_generic("capec", n)
    return {"count": n}


def _stats_capec() -> Dict[str, Any]:
    from db.database import SessionLocal
    from api.models.models import ThreatLibrary
    n = 0
    db = SessionLocal()
    try:
        n = db.query(ThreatLibrary).filter(ThreatLibrary.source == "capec").count()
    except Exception:
        pass
    finally:
        db.close()
    s = _generic_stats("capec")
    s["count"] = n
    return s


def _sync_frameworks() -> Dict[str, Any]:
    """Re-run framework compliance recompute across every client.

    Framework catalog definitions (NIST CSF, NIST 800-53, CIS v8, OWASP
    Top 10, GDPR, ISO 27001, SOC 2, PCI DSS) are bundled with the app —
    there's no external feed to download. What this sync does is force a
    fresh recompute of every client's compliance assessment using the
    current catalog and finding data. Useful after bulk finding edits or
    when a new control mapping is added.
    """
    from db.database import SessionLocal
    from api.models.models import Client
    from services.compliance import recompute_all_frameworks_for_client

    db = SessionLocal()
    client_count = 0
    try:
        for c in db.query(Client.id).all():
            try:
                recompute_all_frameworks_for_client(db, c.id)
                client_count += 1
            except Exception:
                logger.exception("Framework recompute failed for client %s", c.id)
    finally:
        db.close()

    _record_generic("frameworks", client_count, {"clients_recomputed": client_count})
    return {"count": client_count}


def _stats_frameworks() -> Dict[str, Any]:
    s = _generic_stats("frameworks")
    return s


# ── Registry ─────────────────────────────────────────────────────────────────


@dataclass
class SyncFeed:
    id: str
    name: str
    category: str
    description: str
    source_url: str
    sync_fn: Callable[[], Dict[str, Any]]
    stats_fn: Callable[[], Dict[str, Any]]
    item_label: str = "entries"


REGISTRY: Dict[str, SyncFeed] = {
    "epss": SyncFeed(
        id="epss",
        name="EPSS — Exploit Prediction Scoring",
        category="threat_intel",
        description=(
            "FIRST.org's exploit probability score for every CVE. Drives the EPSS factor in "
            "the Risk Priority Score so we don't treat every CVSS 9 the same way."
        ),
        source_url="https://www.first.org/epss/",
        sync_fn=_sync_epss,
        stats_fn=_stats_epss,
        item_label="CVE scores",
    ),
    "kev": SyncFeed(
        id="kev",
        name="CISA KEV — Known Exploited Vulnerabilities",
        category="threat_intel",
        description=(
            "CISA's authoritative list of CVEs confirmed exploited in the wild. KEV-listed "
            "CVEs multiply RPS by 2× (3× when flagged ransomware)."
        ),
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        sync_fn=_sync_kev,
        stats_fn=_stats_kev,
        item_label="catalog entries",
    ),
    "nvd_recent": SyncFeed(
        id="nvd_recent",
        name="NVD — Recent CVEs (last 8 days)",
        category="cve",
        description=(
            "NIST NVD 2.0 API — CVEs modified in the last 8 days. Enriches findings with "
            "CVSS, CWE list, and a short description. Faster with a platform NVD API key."
        ),
        source_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        sync_fn=_sync_nvd_recent,
        stats_fn=_stats_nvd_recent,
        item_label="CVE entries cached",
    ),
    "frameworks": SyncFeed(
        id="frameworks",
        name="Frameworks & Standards — recompute compliance",
        category="framework",
        description=(
            "Re-runs the compliance recompute for every client using the bundled catalog "
            "(NIST CSF, NIST 800-53, CIS v8, OWASP Top 10, GDPR, ISO 27001, SOC 2, PCI DSS). "
            "Use after bulk finding edits or new control mappings."
        ),
        source_url="https://github.com/gulatidh/NexGenCyberAI/tree/main/backend",
        sync_fn=_sync_frameworks,
        stats_fn=_stats_frameworks,
        item_label="clients recomputed",
    ),
    "attack": SyncFeed(
        id="attack",
        name="MITRE ATT&CK — Enterprise techniques",
        category="threat_library",
        description=(
            "MITRE's enterprise adversary playbook. Stored in the threat_library "
            "table so the Threat Modeler buddy can cite real T-IDs (T1190, T1078, "
            "etc.) instead of hallucinating numbers."
        ),
        source_url="https://github.com/mitre/cti/tree/master/enterprise-attack",
        sync_fn=_sync_attack,
        stats_fn=_stats_attack,
        item_label="techniques cached",
    ),
    "capec": SyncFeed(
        id="capec",
        name="MITRE CAPEC — Common Attack Pattern Enumeration",
        category="threat_library",
        description=(
            "MITRE's catalog of attack patterns. Mapped to STRIDE buckets via "
            "CAPEC's consequences scope. The Threat Modeler buddy cites CAPEC-NN "
            "refs from this table instead of inventing them."
        ),
        source_url="https://capec.mitre.org/",
        sync_fn=_sync_capec,
        stats_fn=_stats_capec,
        item_label="attack patterns cached",
    ),
}


# ── Scheduling ───────────────────────────────────────────────────────────────
#
# Cadence for the background refresh that runs on the shared APScheduler. All
# in UTC; admins can still hit "Sync" at any time to force a refresh.
# Frameworks recompute is intentionally excluded — it's a bulk DB rewrite, not
# an external feed.
SCHEDULES: Dict[str, Dict[str, str]] = {
    "epss":       {"cron": "15 3 * * *",   "label": "Daily · 03:15 UTC"},
    "kev":        {"cron": "30 3 * * *",   "label": "Daily · 03:30 UTC"},
    "nvd_recent": {"cron": "0 */6 * * *",  "label": "Every 6 hours"},
    "attack":     {"cron": "0 4 * * 0",    "label": "Weekly · Sun 04:00 UTC"},
    "capec":      {"cron": "15 4 * * 0",   "label": "Weekly · Sun 04:15 UTC"},
}


def _feed_job_id(feed_id: str) -> str:
    return f"sync-feed:{feed_id}"


def _scheduled_sync_job(feed_id: str) -> None:
    """APScheduler entry point — calls the same sync function the admin
    button calls. Records the last attempt in the generic stats blob
    regardless of success so the UI can show 'scheduled run failed'."""
    rec = _read_generic_stats()
    info = rec.setdefault(feed_id, {})
    try:
        result = sync_feed(feed_id)
        ok = bool(result.get("ok"))
        info["last_scheduled_at"] = datetime.now(timezone.utc).isoformat()
        info["last_scheduled_ok"] = ok
        info["last_scheduled_error"] = None if ok else result.get("error")
        _write_generic_stats(rec)
    except Exception as exc:
        logger.exception("Scheduled sync for %s crashed", feed_id)
        info["last_scheduled_at"] = datetime.now(timezone.utc).isoformat()
        info["last_scheduled_ok"] = False
        info["last_scheduled_error"] = str(exc)
        _write_generic_stats(rec)


def start_feed_schedules() -> None:
    """Register every feed in SCHEDULES on the shared APScheduler.
    Idempotent: safe to call once from FastAPI startup."""
    try:
        from apscheduler.triggers.cron import CronTrigger
        from services.mission_scheduler import get_scheduler
    except Exception:
        logger.exception("APScheduler / mission_scheduler unavailable; skipping feed schedules")
        return
    sched = get_scheduler()
    if sched is None:
        logger.warning("Shared scheduler not running; feed schedules will not be registered")
        return
    for fid, spec in SCHEDULES.items():
        if fid not in REGISTRY:
            continue
        try:
            parts = spec["cron"].split()
            if len(parts) != 5:
                raise ValueError(f"Invalid cron: {spec['cron']!r}")
            minute, hour, day, month, dow = parts
            trigger = CronTrigger(
                minute=minute, hour=hour, day=day, month=month, day_of_week=dow,
                timezone="UTC",
            )
            sched.add_job(
                _scheduled_sync_job,
                trigger=trigger,
                args=[fid],
                id=_feed_job_id(fid),
                replace_existing=True,
                misfire_grace_time=60 * 60,  # 1-hour grace if app was down
            )
            logger.info("Scheduled feed %s: %s", fid, spec.get("label") or spec["cron"])
        except Exception:
            logger.exception("Failed to schedule feed %s", fid)


def next_feed_run_time(feed_id: str) -> Optional[str]:
    """Return the next scheduled fire time as an ISO string, or None when
    the feed isn't scheduled / scheduler isn't running."""
    try:
        from services.mission_scheduler import get_scheduler
    except Exception:
        return None
    sched = get_scheduler()
    if sched is None:
        return None
    job = sched.get_job(_feed_job_id(feed_id))
    if not job or not job.next_run_time:
        return None
    return job.next_run_time.astimezone(timezone.utc).isoformat()


def list_feeds() -> List[Dict[str, Any]]:
    """Return every registered feed with its current stats merged in."""
    out: List[Dict[str, Any]] = []
    for feed in REGISTRY.values():
        try:
            stats = feed.stats_fn() or {}
        except Exception as exc:
            logger.exception("Stats lookup failed for feed %s", feed.id)
            stats = {"error": str(exc)}
        sched_spec = SCHEDULES.get(feed.id)
        out.append({
            "id": feed.id,
            "name": feed.name,
            "category": feed.category,
            "description": feed.description,
            "source_url": feed.source_url,
            "item_label": feed.item_label,
            "count": stats.get("count", 0),
            "last_synced_at": stats.get("last_synced_at"),
            "schedule_cron": sched_spec["cron"] if sched_spec else None,
            "schedule_label": sched_spec["label"] if sched_spec else None,
            "next_run_at": next_feed_run_time(feed.id) if sched_spec else None,
            "extra": {k: v for k, v in stats.items() if k not in ("count", "last_synced_at")},
        })
    return out


def sync_feed(feed_id: str) -> Dict[str, Any]:
    feed = REGISTRY.get(feed_id)
    if not feed:
        return {"ok": False, "error": f"Unknown feed: {feed_id}"}
    try:
        result = feed.sync_fn() or {}
        return {"ok": True, "id": feed_id, **result}
    except Exception as exc:
        logger.exception("Sync failed for feed %s", feed_id)
        return {"ok": False, "id": feed_id, "error": str(exc)}


def feed_entries(feed_id: str, db, limit: int = 100, q: Optional[str] = None) -> Dict[str, Any]:
    """Return a sample of the actual entries a feed has synced, for the Sync
    page 'view entries' drawer. Shape: {id, total, rows[], note?}. `rows` are
    dicts; the UI derives columns from the keys."""
    fid = (feed_id or "").lower()

    if fid in ("attack", "capec"):
        from api.models.models import ThreatLibrary
        base = db.query(ThreatLibrary).filter(ThreatLibrary.source == fid)
        total = base.count()
        if q:
            like = f"%{q}%"
            base = base.filter(
                (ThreatLibrary.source_id.ilike(like)) | (ThreatLibrary.name.ilike(like))
            )
        rows = base.order_by(ThreatLibrary.source_id).limit(limit).all()
        def _cwes(r):
            v = r.related_cwes
            return ", ".join(v) if isinstance(v, list) else (v or "")
        return {
            "id": fid, "total": total,
            "rows": [{
                "id": r.source_id, "name": r.name,
                "category": r.category or "", "cwes": _cwes(r),
                "description": (r.description or "")[:200],
            } for r in rows],
        }

    if fid == "epss":
        from services.threat_intel import sample_epss, epss_total
        return {"id": fid, "total": epss_total(), "rows": sample_epss(limit, q)}

    if fid == "kev":
        from services.threat_intel import sample_kev, kev_total
        return {"id": fid, "total": kev_total(), "rows": sample_kev(limit, q)}

    if fid in ("nvd_recent", "nvd"):
        cache_path = _CACHE_DIR / "nvd_cve_cache.json"
        if not cache_path.exists():
            return {"id": fid, "total": 0, "rows": []}
        try:
            data = json.loads(cache_path.read_text())
        except Exception:
            return {"id": fid, "total": 0, "rows": []}
        items = list(data.items())
        if q:
            ql = q.upper()
            items = [(k, v) for k, v in items if ql in k.upper()]
        rows = [{
            "cve": k, "cvss_v3": v.get("cvss_v3"),
            "cwes": ", ".join(v.get("cwes") or []),
            "description": (v.get("description") or "")[:200],
        } for k, v in items[:limit]]
        return {"id": fid, "total": len(data), "rows": rows}

    return {"id": fid, "total": 0, "rows": [],
            "note": "This feed recomputes compliance and has no row-level entries to list."}
