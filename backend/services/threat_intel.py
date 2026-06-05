"""Threat-intel cache for EPSS (FIRST.org) and CISA KEV.

Both feeds are public, free, and updated daily. We download them once a
day, hold them in memory as dicts keyed by CVE ID, and persist a JSON
snapshot to `backend/data/threat_intel_cache.json` so a restart doesn't
require an immediate re-download.

Public surface:
    get_epss(cve_id)         -> {"score": 0.0–1.0, "percentile": 0.0–1.0} | None
    get_kev(cve_id)          -> KEV row dict | None
    refresh_all(force=False) -> {"epss": int, "kev": int, "errors": [...]}
    stats()                  -> {"epss_count": int, "kev_count": int,
                                 "epss_fetched_at": iso, "kev_fetched_at": iso}

Feeds:
    EPSS: https://epss.cyentia.com/epss_scores-current.csv.gz
        Columns: cve, epss, percentile  (header row + 'model_version' header line)
    KEV : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
        Top-level dict with 'vulnerabilities' list.

All network failures are swallowed — the caller can still call get_epss /
get_kev and will receive None until the next refresh succeeds.
"""
from __future__ import annotations
import csv
import gzip
import io
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

from core.paths import data_dir
# Persistent, worker-shared cache dir (/home/data on Azure). See core/paths.py.
_CACHE_DIR = data_dir()
_CACHE_FILE = _CACHE_DIR / "threat_intel_cache.json"

# In-memory caches. Read under _lock; the dicts themselves are replaced
# wholesale on refresh, so reads can drop the lock once they've grabbed a
# local reference.
_lock = threading.RLock()
_epss: Dict[str, Dict[str, float]] = {}
_kev: Dict[str, Dict[str, Any]] = {}
_epss_fetched_at: Optional[datetime] = None
_kev_fetched_at: Optional[datetime] = None
_loaded_from_disk = False
_loaded_mtime: Optional[float] = None  # mtime of the cache file we last loaded


# ── Public API ───────────────────────────────────────────────────────────────


def get_epss(cve_id: str) -> Optional[Dict[str, float]]:
    """Return {'score': float, 'percentile': float} for the CVE or None."""
    if not cve_id:
        return None
    _ensure_loaded()
    return _epss.get(cve_id.upper())


def get_kev(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return the CISA KEV row dict for the CVE or None. Keys include:
    'dateAdded', 'shortDescription', 'requiredAction', 'dueDate',
    'knownRansomwareCampaignUse'."""
    if not cve_id:
        return None
    _ensure_loaded()
    return _kev.get(cve_id.upper())


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "epss_count": len(_epss),
        "kev_count": len(_kev),
        "epss_fetched_at": _epss_fetched_at.isoformat() if _epss_fetched_at else None,
        "kev_fetched_at": _kev_fetched_at.isoformat() if _kev_fetched_at else None,
    }


def refresh_all(force: bool = False) -> Dict[str, Any]:
    """Refresh both feeds. Returns counts + per-feed error strings (if any).

    `force=False` skips a feed when the in-memory snapshot is younger than
    23 hours — protects against accidental scheduler double-fires.
    """
    result: Dict[str, Any] = {"epss": 0, "kev": 0, "errors": []}
    _ensure_loaded()
    now = datetime.now(timezone.utc)

    if force or not _epss_fetched_at or (now - _epss_fetched_at).total_seconds() > 23 * 3600:
        try:
            result["epss"] = _refresh_epss()
        except Exception as exc:
            logger.exception("EPSS refresh failed")
            result["errors"].append(f"epss: {exc}")
    else:
        result["epss"] = len(_epss)

    if force or not _kev_fetched_at or (now - _kev_fetched_at).total_seconds() > 23 * 3600:
        try:
            result["kev"] = _refresh_kev()
        except Exception as exc:
            logger.exception("KEV refresh failed")
            result["errors"].append(f"kev: {exc}")
    else:
        result["kev"] = len(_kev)

    _persist_to_disk()
    return result


# ── Internal: disk persistence ───────────────────────────────────────────────


def _ensure_loaded() -> None:
    """Load the on-disk cache, re-reading if another worker has refreshed it
    since (the file lives on the shared /home mount). Only re-parses when the
    file's mtime changes, so steady-state calls are a cheap stat()."""
    global _loaded_from_disk, _loaded_mtime
    def _mtime():
        try:
            return _CACHE_FILE.stat().st_mtime if _CACHE_FILE.exists() else None
        except Exception:
            return None
    if _loaded_from_disk and _mtime() == _loaded_mtime:
        return
    with _lock:
        m = _mtime()
        if _loaded_from_disk and m == _loaded_mtime:
            return
        _load_from_disk()
        _loaded_from_disk = True
        _loaded_mtime = m


def _load_from_disk() -> None:
    global _epss, _kev, _epss_fetched_at, _kev_fetched_at
    if not _CACHE_FILE.exists():
        return
    try:
        with _CACHE_FILE.open("r") as f:
            data = json.load(f)
        _epss = data.get("epss") or {}
        _kev = data.get("kev") or {}
        ef = data.get("epss_fetched_at")
        kf = data.get("kev_fetched_at")
        _epss_fetched_at = datetime.fromisoformat(ef) if ef else None
        _kev_fetched_at = datetime.fromisoformat(kf) if kf else None
        logger.info("Threat-intel cache loaded from disk (epss=%d, kev=%d)", len(_epss), len(_kev))
    except Exception:
        logger.exception("Failed to read threat-intel cache; starting empty")
        _epss, _kev = {}, {}
        _epss_fetched_at, _kev_fetched_at = None, None


def _persist_to_disk() -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = _CACHE_FILE.with_suffix(".json.tmp")
        with tmp.open("w") as f:
            json.dump({
                "epss": _epss,
                "kev": _kev,
                "epss_fetched_at": _epss_fetched_at.isoformat() if _epss_fetched_at else None,
                "kev_fetched_at": _kev_fetched_at.isoformat() if _kev_fetched_at else None,
            }, f)
        os.replace(tmp, _CACHE_FILE)
        # Record the mtime we just wrote so this worker doesn't needlessly
        # re-read its own write on the next _ensure_loaded().
        global _loaded_mtime, _loaded_from_disk
        try:
            _loaded_mtime = _CACHE_FILE.stat().st_mtime
            _loaded_from_disk = True
        except Exception:
            pass
    except Exception:
        logger.exception("Failed to persist threat-intel cache to %s", _CACHE_FILE)


# ── Internal: feed download + parse ──────────────────────────────────────────


def _refresh_epss() -> int:
    """Download + parse EPSS. The CSV ships with a #model_version header
    above the column header, so skip until we see the 'cve,' column row."""
    global _epss, _epss_fetched_at
    logger.info("Refreshing EPSS feed from %s", EPSS_URL)
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        resp = client.get(EPSS_URL)
        resp.raise_for_status()
        raw = resp.content
    # The feed is gzip-compressed CSV.
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
        text = gz.read().decode("utf-8", errors="replace")
    new_map: Dict[str, Dict[str, float]] = {}
    reader = csv.reader(io.StringIO(text))
    header_seen = False
    for row in reader:
        if not row:
            continue
        if row[0].startswith("#"):
            continue
        if not header_seen:
            # Expecting "cve,epss,percentile"
            if row[0].strip().lower() == "cve":
                header_seen = True
            continue
        if len(row) < 3:
            continue
        cve = (row[0] or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        try:
            new_map[cve] = {
                "score": float(row[1]),
                "percentile": float(row[2]),
            }
        except ValueError:
            continue
    with _lock:
        _epss = new_map
        _epss_fetched_at = datetime.now(timezone.utc)
    logger.info("EPSS cached: %d CVEs", len(new_map))
    return len(new_map)


def _refresh_kev() -> int:
    global _kev, _kev_fetched_at
    logger.info("Refreshing CISA KEV feed from %s", KEV_URL)
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        resp = client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
    new_map: Dict[str, Dict[str, Any]] = {}
    for v in data.get("vulnerabilities") or []:
        cve = (v.get("cveID") or "").strip().upper()
        if not cve:
            continue
        new_map[cve] = {
            "dateAdded": v.get("dateAdded"),
            "vendorProject": v.get("vendorProject"),
            "product": v.get("product"),
            "vulnerabilityName": v.get("vulnerabilityName"),
            "shortDescription": v.get("shortDescription"),
            "requiredAction": v.get("requiredAction"),
            "dueDate": v.get("dueDate"),
            "knownRansomwareCampaignUse": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
        }
    with _lock:
        _kev = new_map
        _kev_fetched_at = datetime.now(timezone.utc)
    logger.info("KEV cached: %d CVEs", len(new_map))
    return len(new_map)
