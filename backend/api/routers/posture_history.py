"""Posture history — daily snapshots and trend data per client."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone, timedelta

from api.models.models import PostureSnapshot, Client, Finding, Scan
from api.schemas.schemas import PostureSnapshotResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

router = APIRouter(prefix="/clients/{client_id}/posture-history", tags=["posture-history"])


@router.get("/", response_model=List[PostureSnapshotResponse])
async def list_snapshots(
    client_id: str,
    days: int = 90,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return snapshots for the last N days ordered ascending (for charting)."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return (
        db.query(PostureSnapshot)
        .filter(PostureSnapshot.client_id == client_id, PostureSnapshot.captured_at >= since)
        .order_by(PostureSnapshot.captured_at.asc())
        .all()
    )


@router.get("/scan-summary")
async def scan_posture_summary(
    client_id: str,
    scan_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return posture metrics computed live from a specific scan's findings."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.client_id == client_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    open_counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
        counts[sev] = counts.get(sev, 0) + 1
        if f.status == "open":
            open_counts[sev] = open_counts.get(sev, 0) + 1

    connector_type = scan.connector_type.value if hasattr(scan.connector_type, "value") else str(scan.connector_type or "")
    return {
        "scan_id": scan_id,
        "scan_name": scan.name,
        "connector_type": connector_type,
        "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "total_findings": sum(counts.values()),
        "total_open": sum(open_counts.values()),
        "by_severity": counts,
        "open_by_severity": open_counts,
    }


@router.post("/snapshot", response_model=PostureSnapshotResponse)
async def trigger_snapshot(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_editor_anywhere),
):
    """Manually trigger a posture snapshot for this client."""
    from services.posture_snapshot import take_snapshot
    return take_snapshot(db, client_id)
