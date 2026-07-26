"""Risk register CRUD endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from api.models.models import Finding, Risk, Scan
from api.schemas.schemas import RiskCreate, RiskResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_scoped_role, AccessRole, AccessScope
from services.risk_scoring import clamp_scale, compute_risk_score

router = APIRouter(prefix="/clients/{client_id}/risks", tags=["risks"])


@router.get("/", response_model=List[RiskResponse])
async def list_risks(
    client_id: str,
    project_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    risks = db.query(Risk).filter(Risk.client_id == client_id).all()
    if not project_id:
        return risks
    # Risk has no project_id of its own — derive: keep risks whose finding_ids
    # contain at least one finding whose scan.project_id matches.
    project_finding_ids = {
        fid for (fid,) in (
            db.query(Finding.id)
            .join(Scan, Finding.scan_id == Scan.id)
            .filter(Scan.client_id == client_id, Scan.project_id == project_id)
            .all()
        )
    }
    return [
        r for r in risks
        if any(fid in project_finding_ids for fid in (r.finding_ids or []))
    ]


@router.post("/", response_model=RiskResponse, status_code=201)
async def create_risk(client_id: str, payload: RiskCreate, db: Session = Depends(get_db), user=Depends(get_current_user)):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    data = payload.model_dump()
    data["likelihood"] = clamp_scale(data.get("likelihood"), 5)
    data["impact"] = clamp_scale(data.get("impact"), 5)
    risk = Risk(
        client_id=client_id,
        **data,
        risk_score=compute_risk_score(data["likelihood"], data["impact"]),
    )
    db.add(risk)
    db.commit()
    db.refresh(risk)
    return risk


@router.get("/{risk_id}", response_model=RiskResponse)
async def get_risk(client_id: str, risk_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    risk = db.query(Risk).filter(Risk.id == risk_id, Risk.client_id == client_id).first()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    return risk


_RISK_UPDATABLE_FIELDS = {
    "title", "description", "likelihood", "impact", "category", "status",
    "owner", "due_date", "mitigation_notes", "assignee_email",
}

@router.patch("/{risk_id}", response_model=RiskResponse)
async def update_risk(client_id: str, risk_id: str, payload: dict, db: Session = Depends(get_db), user=Depends(get_current_user)):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    risk = db.query(Risk).filter(Risk.id == risk_id, Risk.client_id == client_id).first()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    for k, v in payload.items():
        if k in _RISK_UPDATABLE_FIELDS:
            setattr(risk, k, v)
    db.commit()
    db.refresh(risk)
    return risk


@router.delete("/{risk_id}", status_code=204)
async def delete_risk(client_id: str, risk_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    risk = db.query(Risk).filter(Risk.id == risk_id, Risk.client_id == client_id).first()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    db.delete(risk)
    db.commit()
