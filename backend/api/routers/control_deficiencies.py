"""Control Deficiency Register — per-client control gaps from the Compliance agent."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from api.models.models import ControlDeficiency
from api.schemas.schemas import ControlDeficiencyResponse, ControlDeficiencyUpdate
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/control-deficiencies", tags=["control-deficiencies"])


@router.get("/", response_model=List[ControlDeficiencyResponse])
async def list_control_deficiencies(
    client_id: str,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    framework: Optional[str] = None,
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(ControlDeficiency).filter(ControlDeficiency.client_id == client_id)
    if status:
        q = q.filter(ControlDeficiency.status == status)
    if severity:
        q = q.filter(ControlDeficiency.severity == severity)
    if framework:
        q = q.filter(ControlDeficiency.framework == framework)
    if scan_id:
        q = q.filter(ControlDeficiency.scan_id == scan_id)
    return q.order_by(ControlDeficiency.created_at.desc()).all()


@router.patch("/{deficiency_id}", response_model=ControlDeficiencyResponse)
async def update_control_deficiency(
    client_id: str,
    deficiency_id: str,
    payload: ControlDeficiencyUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    entry = db.query(ControlDeficiency).filter(
        ControlDeficiency.id == deficiency_id, ControlDeficiency.client_id == client_id
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Control deficiency not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(entry, field, value)
    db.commit()
    db.refresh(entry)
    return entry


@router.delete("/{deficiency_id}", status_code=204)
async def delete_control_deficiency(
    client_id: str,
    deficiency_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    entry = db.query(ControlDeficiency).filter(
        ControlDeficiency.id == deficiency_id, ControlDeficiency.client_id == client_id
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Control deficiency not found")
    db.delete(entry)
    db.commit()
