"""Risk register CRUD endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from api.models.models import Risk
from api.schemas.schemas import RiskCreate, RiskResponse
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/risks", tags=["risks"])


@router.get("/", response_model=List[RiskResponse])
async def list_risks(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(Risk).filter(Risk.client_id == client_id).all()


@router.post("/", response_model=RiskResponse, status_code=201)
async def create_risk(client_id: str, payload: RiskCreate, db: Session = Depends(get_db), _=Depends(get_current_user)):
    risk = Risk(
        client_id=client_id,
        **payload.model_dump(),
        risk_score=round(payload.likelihood * payload.impact / 2.5, 1),
    )
    db.add(risk)
    db.commit()
    db.refresh(risk)
    return risk


@router.get("/{risk_id}", response_model=RiskResponse)
async def get_risk(client_id: str, risk_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    risk = db.query(Risk).filter(Risk.id == risk_id, Risk.client_id == client_id).first()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    return risk


@router.patch("/{risk_id}", response_model=RiskResponse)
async def update_risk(client_id: str, risk_id: str, payload: dict, db: Session = Depends(get_db), _=Depends(get_current_user)):
    risk = db.query(Risk).filter(Risk.id == risk_id, Risk.client_id == client_id).first()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    for k, v in payload.items():
        setattr(risk, k, v)
    db.commit()
    db.refresh(risk)
    return risk


@router.delete("/{risk_id}", status_code=204)
async def delete_risk(client_id: str, risk_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    risk = db.query(Risk).filter(Risk.id == risk_id, Risk.client_id == client_id).first()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    db.delete(risk)
    db.commit()
