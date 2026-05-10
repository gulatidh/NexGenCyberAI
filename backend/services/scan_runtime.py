"""Per-scan runtime data — keys & secrets that the workflow runner needs to
fetch via GET /scans/config/. Stored in the Scan.summary JSON column under
the `runtime` key so we don't add a new table for one feature.

Schema:
  Scan.summary["runtime"] = {
      "target_url": str,
      "profile": "baseline" | "active",
      "auth_headers": {header_name: header_value, ...},  # decrypted, ZAP-ready
      "exclude_paths": [str, ...],
      "auth_method": str,
  }
"""
from __future__ import annotations
import logging
from typing import Any, Dict, Optional

from db.database import SessionLocal
from api.models.models import Scan

logger = logging.getLogger(__name__)


def set_runtime(scan_id: str, runtime: Dict[str, Any]) -> None:
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.warning("set_runtime: scan %s not found", scan_id)
            return
        summary = dict(scan.summary or {})
        summary["runtime"] = runtime
        scan.summary = summary
        db.commit()
    finally:
        db.close()


def get_runtime(scan_id: str) -> Optional[Dict[str, Any]]:
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        return (scan.summary or {}).get("runtime")
    finally:
        db.close()


def clear_runtime(scan_id: str) -> None:
    """Wipe runtime once the scan has ingested results — never leave auth
    headers persisted longer than necessary."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        summary = dict(scan.summary or {})
        summary.pop("runtime", None)
        scan.summary = summary
        db.commit()
    finally:
        db.close()
