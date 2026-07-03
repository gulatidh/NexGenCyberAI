"""Remediation Action Tracker — per-client action items from the Remediation agent."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
from api.models.models import RemediationAction
from api.schemas.schemas import RemediationActionResponse, RemediationActionUpdate
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/remediation-actions", tags=["remediation-tracker"])


@router.get("/", response_model=List[RemediationActionResponse])
async def list_remediation_actions(
    client_id: str,
    status: Optional[str] = None,
    band: Optional[str] = None,
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(RemediationAction).filter(RemediationAction.client_id == client_id)
    if status:
        q = q.filter(RemediationAction.status == status)
    if band:
        q = q.filter(RemediationAction.band == band)
    if scan_id:
        q = q.filter(RemediationAction.scan_id == scan_id)
    return q.order_by(RemediationAction.priority.asc(), RemediationAction.created_at.desc()).all()


@router.patch("/{action_id}", response_model=RemediationActionResponse)
async def update_remediation_action(
    client_id: str,
    action_id: str,
    payload: RemediationActionUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    action = db.query(RemediationAction).filter(
        RemediationAction.id == action_id, RemediationAction.client_id == client_id
    ).first()
    if not action:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(action, field, value)
    if payload.status == "completed" and not action.completed_at:
        action.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(action)
    return action


@router.delete("/{action_id}", status_code=204)
async def delete_remediation_action(
    client_id: str,
    action_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    action = db.query(RemediationAction).filter(
        RemediationAction.id == action_id, RemediationAction.client_id == client_id
    ).first()
    if not action:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    db.delete(action)
    db.commit()
