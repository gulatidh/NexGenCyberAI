"""Local-filesystem storage for scan binaries (Phase 1).

CodeQL --mode=none binary scanning needs the user's compiled artifacts on
the GitHub Actions runner. The runner can't accept push uploads, so the
backend hosts the file and the workflow fetches it via an HMAC-token
GET. This module owns the path layout, write helpers, and the cleanup
job that purges binaries older than 30 days.

Path layout:
    {BINARIES_ROOT}/{scan_id}/{filename}
        original-cased, sanitized to drop path traversal characters
    {BINARIES_ROOT}/{scan_id}/.meta.json
        {filename, size, sha256, uploaded_at}

BINARIES_ROOT defaults to /home/data/uploads — the App Service `/home`
mount is persistent across restarts. Override via SCAN_BINARIES_DIR env
var for local dev or alternative storage.

Retention: 30 days. Run via the cleanup_old_binaries() function from a
scheduled task or admin endpoint.
"""
from __future__ import annotations
import hashlib
import json
import logging
import os
import re
import shutil
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

DEFAULT_ROOT = "/home/data/uploads"
DEFAULT_RETENTION_DAYS = 30


def root_dir() -> Path:
    root = os.environ.get("SCAN_BINARIES_DIR") or DEFAULT_ROOT
    p = Path(root)
    p.mkdir(parents=True, exist_ok=True)
    return p


def scan_dir(scan_id: str) -> Path:
    # Defensive sanitisation — never trust user-supplied scan IDs to
    # contain ".." or path separators, even though our scans are UUID4.
    safe = re.sub(r"[^a-zA-Z0-9_-]", "", scan_id)
    if not safe:
        raise ValueError("Invalid scan_id")
    p = root_dir() / safe
    p.mkdir(parents=True, exist_ok=True)
    return p


def _sanitize_filename(name: str) -> str:
    """Strip path components and collapse to a safe basename."""
    base = os.path.basename(name or "binary.bin")
    # Allow letters, digits, dot, dash, underscore; collapse the rest.
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._") or "binary.bin"
    return cleaned[:128]


def save_upload(scan_id: str, filename: str, stream: Iterable[bytes]) -> dict:
    """Stream-write an uploaded file into the per-scan directory. Returns
    metadata dict. Existing files in the directory are removed first so a
    re-upload always supersedes the previous one."""
    target_dir = scan_dir(scan_id)
    # Wipe any prior content for this scan so we never serve a stale binary.
    for existing in target_dir.iterdir():
        try:
            existing.unlink()
        except Exception:
            pass

    name = _sanitize_filename(filename)
    final_path = target_dir / name
    sha = hashlib.sha256()
    size = 0
    with final_path.open("wb") as f:
        for chunk in stream:
            if not chunk:
                continue
            f.write(chunk)
            sha.update(chunk)
            size += len(chunk)

    meta = {
        "filename": name,
        "size": size,
        "sha256": sha.hexdigest(),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }
    (target_dir / ".meta.json").write_text(json.dumps(meta))
    logger.info("Stored binary for scan %s: %s (%d bytes)", scan_id, name, size)
    return meta


def get_meta(scan_id: str) -> Optional[dict]:
    meta_file = scan_dir(scan_id) / ".meta.json"
    if not meta_file.exists():
        return None
    try:
        return json.loads(meta_file.read_text())
    except Exception:
        return None


def get_file_path(scan_id: str) -> Optional[Path]:
    """Return the path to the stored binary for a scan, or None."""
    meta = get_meta(scan_id)
    if not meta:
        return None
    p = scan_dir(scan_id) / meta["filename"]
    return p if p.exists() else None


def cleanup_old_binaries(days: int = DEFAULT_RETENTION_DAYS) -> dict:
    """Walk BINARIES_ROOT and delete any per-scan directory whose newest
    file is older than `days`. Returns {scanned: N, removed: M, freed_bytes: …}."""
    root = root_dir()
    cutoff = time.time() - (days * 86400)
    removed = 0
    freed = 0
    scanned = 0
    for child in root.iterdir():
        if not child.is_dir():
            continue
        scanned += 1
        try:
            files = list(child.iterdir())
            if not files:
                shutil.rmtree(child, ignore_errors=True)
                continue
            newest = max(f.stat().st_mtime for f in files)
            if newest < cutoff:
                bytes_in = sum(f.stat().st_size for f in files if f.is_file())
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
                freed += bytes_in
        except Exception:
            logger.exception("cleanup_old_binaries failed for %s", child)
    out = {
        "scanned": scanned,
        "removed": removed,
        "freed_bytes": freed,
        "retention_days": days,
        "ran_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info("Binary cleanup: %s", out)
    return out
