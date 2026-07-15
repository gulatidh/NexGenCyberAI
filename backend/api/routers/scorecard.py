"""Embeddable public scorecard — no auth required, token-gated."""
import secrets
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone
from typing import List

from api.models.models import ScorecardToken, Client, Finding, Risk, Scan
from api.schemas.schemas import ScorecardTokenResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

router = APIRouter(tags=["scorecard"])

_auth_router = APIRouter(prefix="/clients/{client_id}/scorecard", tags=["scorecard"])


@_auth_router.get("/tokens", response_model=List[ScorecardTokenResponse])
async def list_tokens(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(ScorecardToken).filter(ScorecardToken.client_id == client_id).all()


@_auth_router.post("/tokens", response_model=ScorecardTokenResponse, dependencies=[Depends(require_editor_anywhere)])
async def create_token(client_id: str, label: str = "Public Scorecard", db: Session = Depends(get_db), user=Depends(get_current_user)):
    tok = ScorecardToken(
        client_id=client_id,
        token=secrets.token_hex(32),
        label=label,
        created_by=user.get("email") or user.get("preferred_username") or "",
    )
    db.add(tok)
    db.commit()
    db.refresh(tok)
    return tok


@_auth_router.delete("/tokens/{token_id}", dependencies=[Depends(require_editor_anywhere)])
async def revoke_token(client_id: str, token_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    tok = db.query(ScorecardToken).filter(ScorecardToken.id == token_id, ScorecardToken.client_id == client_id).first()
    if not tok:
        raise HTTPException(status_code=404, detail="Token not found")
    tok.is_active = False
    db.commit()
    return {"revoked": True}


# Public endpoint — no auth, token-gated
@router.get("/public/scorecard/{token}")
async def public_scorecard(token: str, db: Session = Depends(get_db)):
    """Public endpoint — returns sanitised posture summary for embedding."""
    tok = db.query(ScorecardToken).filter(
        ScorecardToken.token == token,
        ScorecardToken.is_active == True,
    ).first()
    if not tok:
        raise HTTPException(status_code=404, detail="Scorecard not found or expired")
    if tok.expires_at and tok.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="Scorecard link has expired")

    client_id = tok.client_id
    client = db.query(Client).filter(Client.id == client_id).first()

    open_findings = (
        db.query(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open")
        .scalar() or 0
    )
    critical = (
        db.query(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open", Finding.severity == "critical")
        .scalar() or 0
    )
    open_risks = db.query(func.count(Risk.id)).filter(Risk.client_id == client_id, Risk.status == "open").scalar() or 0

    # Simple posture score: 100 - (critical*10 + high*3 + medium*1), floored at 0
    high_count = (
        db.query(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open", Finding.severity == "high")
        .scalar() or 0
    )
    score = max(0, min(100, 100 - critical * 10 - high_count * 3 - (open_findings - critical - high_count)))

    return {
        "client_name": client.name if client else "Unknown",
        "label": tok.label,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "posture_score": score,
        "open_findings": open_findings,
        "critical_findings": critical,
        "open_risks": open_risks,
        "score_label": "Critical" if score < 40 else "At Risk" if score < 60 else "Fair" if score < 80 else "Good",
    }


# Combine both into main router — export both
router.include_router(_auth_router)
