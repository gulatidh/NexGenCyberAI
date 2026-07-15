"""Posture history — daily snapshots and trend data per client."""
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone, timedelta

from api.models.models import PostureSnapshot, Client
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


@router.post("/snapshot", response_model=PostureSnapshotResponse)
async def trigger_snapshot(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_editor_anywhere),
):
    """Manually trigger a posture snapshot for this client."""
    from services.posture_snapshot import take_snapshot
    return take_snapshot(db, client_id)
