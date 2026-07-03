"""Threat Intelligence Register — per-client threat entries from the Threat Intel agent."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from api.models.models import ThreatEntry
from api.schemas.schemas import ThreatEntryResponse, ThreatEntryUpdate
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/threat-register", tags=["threat-register"])


@router.get("/", response_model=List[ThreatEntryResponse])
async def list_threat_entries(
    client_id: str,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(ThreatEntry).filter(ThreatEntry.client_id == client_id)
    if status:
        q = q.filter(ThreatEntry.status == status)
    if severity:
        q = q.filter(ThreatEntry.severity == severity)
    if scan_id:
        q = q.filter(ThreatEntry.scan_id == scan_id)
    return q.order_by(ThreatEntry.created_at.desc()).all()


@router.patch("/{entry_id}", response_model=ThreatEntryResponse)
async def update_threat_entry(
    client_id: str,
    entry_id: str,
    payload: ThreatEntryUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    entry = db.query(ThreatEntry).filter(
        ThreatEntry.id == entry_id, ThreatEntry.client_id == client_id
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Threat entry not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(entry, field, value)
    db.commit()
    db.refresh(entry)
    return entry


@router.delete("/{entry_id}", status_code=204)
async def delete_threat_entry(
    client_id: str,
    entry_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    entry = db.query(ThreatEntry).filter(
        ThreatEntry.id == entry_id, ThreatEntry.client_id == client_id
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Threat entry not found")
    db.delete(entry)
    db.commit()
