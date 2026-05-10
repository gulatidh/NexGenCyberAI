"""HMAC-signed per-scan tokens used by the ZAP runner workflow to call back.

The workflow does not have a user bearer token. Instead the backend mints
a short-lived token bound to a single scan_id, and the workflow uses it on
both `GET /scans/config/?scan_id=...&scan_token=...` and
`POST /scans/ingest/`. Token is valid until the scan TTL expires
(default 6h — full scans can run that long).

Format: base64url(scan_id|expires_unix|hmac_sha256(secret, scan_id|expires_unix))
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import os
import time
from typing import Optional

from core.config import get_settings

DEFAULT_TTL_SECONDS = 6 * 60 * 60  # 6 hours


def _secret() -> bytes:
    s = os.environ.get("SCAN_INGEST_SECRET") or get_settings().SECRET_KEY
    return s.encode("utf-8")


def mint_scan_token(scan_id: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    expires = int(time.time()) + max(60, ttl_seconds)
    payload = f"{scan_id}|{expires}".encode("utf-8")
    sig = hmac.new(_secret(), payload, hashlib.sha256).hexdigest()
    raw = f"{scan_id}|{expires}|{sig}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def verify_scan_token(token: str, expected_scan_id: Optional[str] = None) -> Optional[str]:
    """Return the scan_id if the token is valid; else None.

    If `expected_scan_id` is provided, also enforces the binding.
    """
    if not token:
        return None
    try:
        # Restore base64 padding
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
        parts = raw.split("|")
        if len(parts) != 3:
            return None
        scan_id, expires_s, sig = parts
        expires = int(expires_s)
    except Exception:
        return None

    if int(time.time()) > expires:
        return None
    payload = f"{scan_id}|{expires}".encode("utf-8")
    expected_sig = hmac.new(_secret(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    if expected_scan_id and scan_id != expected_scan_id:
        return None
    return scan_id
