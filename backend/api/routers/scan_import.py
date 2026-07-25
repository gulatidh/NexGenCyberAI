"""
Scan Import router — upload offline scan result files.

Endpoints:
  POST /clients/{client_id}/scans/import/parse    — parse & preview (no DB write)
  POST /clients/{client_id}/scans/import/commit   — save to DB
  GET  /clients/{client_id}/scans/import/history  — list import scans
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from api.models.models import ConnectorType, Finding, Scan, ScanStatus, ScanType
from core.authz import require_editor_anywhere
from core.security import get_current_user
from db.database import get_db
from services.scan_importer import compute_delta, import_scan_file

router = APIRouter(
    prefix="/clients/{client_id}/scans/import",
    tags=["scan-import"],
)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

# Scans that were created by the importer carry "upload" as the name prefix
# and store format metadata in raw_context (JSON string).
_IMPORT_NAME_PREFIX = "Import:"


def _is_import_scan(scan: Scan) -> bool:
    """True when the scan was created by the importer (raw_context has source_format)."""
    if not scan.raw_context:
        return False
    try:
        ctx = json.loads(scan.raw_context) if isinstance(scan.raw_context, str) else scan.raw_context
        return "source_format" in ctx
    except Exception:
        return False


@router.post("/parse")
async def parse_scan_file(
    client_id: str,
    file: UploadFile = File(...),
    tool_hint: str = Form(default=""),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Parse an uploaded scan file and return a preview of findings — no DB write."""
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 50 MB)")
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    from core.config import get_settings
    settings = get_settings()

    fmt, findings = await import_scan_file(
        content,
        filename=file.filename or "upload",
        tool_hint=tool_hint,
        nvd_api_key=settings.NVD_API_KEY,
    )

    # Compute delta against existing open findings for this client (via scan join)
    existing = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.status == "open",
            Finding.suppressed_at.is_(None),
        )
        .all()
    )
    delta = compute_delta(findings, existing)

    sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    avg_conf_pct = (
        round(sum(f.confidence for f in findings) / len(findings) * 100) if findings else 0
    )

    return {
        # Field names match the frontend ImportPreview interface exactly
        "detected_format": fmt,
        "finding_count": len(findings),
        "severity_breakdown": sev_counts,
        "avg_confidence": avg_conf_pct,
        "new_count": delta.new_count,
        "fixed_count": delta.fixed_count,
        "persisting_count": delta.persisting_count,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "resource": f.resource_id,
                "cve_id": f.cve_id,
                "confidence": round(f.confidence * 100),
            }
            for f in findings
        ],
    }


@router.post("/commit", status_code=201)
async def commit_scan_import(
    client_id: str,
    file: UploadFile = File(...),
    tool_hint: str = Form(default=""),
    scan_name: str = Form(default=""),
    db: Session = Depends(get_db),
    user=Depends(require_editor_anywhere),
):
    """Parse a scan file and save findings to the database."""
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 50 MB)")
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    from core.config import get_settings
    settings = get_settings()

    fmt, findings = await import_scan_file(
        content,
        filename=file.filename or "upload",
        tool_hint=tool_hint,
        nvd_api_key=settings.NVD_API_KEY,
    )

    if not findings:
        raise HTTPException(status_code=422, detail="No findings could be extracted from the file")

    # Resolve initiator identity
    initiator = (
        user.get("preferred_username")
        or user.get("upn")
        or user.get("email")
        or user.get("sub")
        or "unknown"
    )

    # Create a Scan record for this import.
    # scan_type is non-nullable; use VULNERABILITY as the canonical type for imported results.
    raw_ctx = json.dumps({
        "source_format": fmt,
        "filename": file.filename,
        "tool_hint": tool_hint,
        "import": True,
    })
    scan = Scan(
        id=str(uuid.uuid4()),
        client_id=client_id,
        connector_type=ConnectorType.UPLOAD,
        scan_type=ScanType.VULNERABILITY,
        status=ScanStatus.COMPLETED,
        target=file.filename or "uploaded_file",
        name=scan_name or f"{_IMPORT_NAME_PREFIX} {file.filename or 'upload'} ({fmt})",
        initiated_by=initiator,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        raw_context=raw_ctx,
        progress_message=f"Imported {len(findings)} findings from {fmt} format",
    )
    db.add(scan)
    db.flush()  # populate scan.id before referencing it in findings

    # Ingest findings — Finding.scan_id is the FK; client_id is implicit via scan.
    finding_objs = []
    for pf in findings:
        kwargs = pf.to_finding_kwargs(scan.id, fmt)
        finding_objs.append(Finding(**kwargs))
    db.bulk_save_objects(finding_objs)

    # Compute delta against existing open findings (excluding this new scan)
    existing = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.status == "open",
            Finding.scan_id != scan.id,
            Finding.suppressed_at.is_(None),
        )
        .all()
    )
    delta = compute_delta(findings, existing)

    db.commit()

    return {
        "scan_id": scan.id,
        "format": fmt,
        "findings_imported": len(findings),
        "delta": {
            "new": delta.new_count,
            "fixed": delta.fixed_count,
            "persisting": delta.persisting_count,
        },
    }


@router.get("/history")
def import_history(
    client_id: str,
    limit: int = 20,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List previous import scans for this client."""
    # Identify import scans by presence of "Import:" name prefix or raw_context import flag.
    scans = (
        db.query(Scan)
        .filter(Scan.client_id == client_id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    results = []
    for s in scans:
        if not _is_import_scan(s):
            continue
        try:
            ctx = json.loads(s.raw_context) if isinstance(s.raw_context, str) else (s.raw_context or {})
        except Exception:
            ctx = {}
        finding_count = db.query(Finding).filter(Finding.scan_id == s.id).count()
        results.append({
            "id": s.id,
            "scan_name": s.name,
            "target": s.target,
            "finding_count": finding_count,
            "detected_format": ctx.get("source_format", "unknown"),
            "tool_hint": ctx.get("tool_hint", ""),
            "created_at": s.created_at,
        })
        if len(results) >= limit:
            break
    return results
