"""Risk register CRUD endpoints."""
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from api.models.models import Client, Finding, Risk, RiskLevel, Scan
from api.schemas.schemas import RiskCreate, RiskResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_scoped_role, AccessRole, AccessScope
from core.ai_providers import get_llm
from services.risk_scoring import clamp_scale, compute_risk_score

router = APIRouter(prefix="/clients/{client_id}/risks", tags=["risks"])


def _residual_label(score: int) -> str:
    if score <= 4: return "low"
    if score <= 9: return "medium"
    if score <= 12: return "medium_high"
    if score <= 20: return "high"
    return "critical"


_RISK_LEVEL_FROM_SCORE = [
    (range(1, 5),   RiskLevel.LOW),
    (range(5, 10),  RiskLevel.MEDIUM),
    (range(10, 13), RiskLevel.MEDIUM),
    (range(13, 21), RiskLevel.HIGH),
    (range(21, 26), RiskLevel.CRITICAL),
]


def _matrix_to_level(score: int) -> RiskLevel:
    for rng, level in _RISK_LEVEL_FROM_SCORE:
        if score in rng:
            return level
    return RiskLevel.HIGH


class ReevaluatePayload(BaseModel):
    wizard_data: Dict[str, Any]
    measures: List[Dict[str, Any]] = []
    extra_context: str = ""


@router.get("/export")
async def export_risks(
    client_id: str,
    format: str = Query("pdf", regex="^(pdf|docx)$"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    client = db.query(Client).filter(Client.id == client_id).first()
    client_name = client.name if client else client_id
    risks = db.query(Risk).filter(Risk.client_id == client_id).order_by(Risk.risk_score.desc().nullslast()).all()

    from services.risk_export import generate_risk_register_pdf, generate_risk_register_docx
    if format == "pdf":
        buf = generate_risk_register_pdf(client_name, risks)
        return StreamingResponse(
            buf,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=risk-register-{client_id[:8]}.pdf"},
        )
    else:
        buf = generate_risk_register_docx(client_name, risks)
        return StreamingResponse(
            buf,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename=risk-register-{client_id[:8]}.docx"},
        )


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


@router.get("/{risk_id}/export")
async def export_single_risk(
    client_id: str, risk_id: str,
    format: str = Query("pdf", regex="^(pdf|docx)$"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    client = db.query(Client).filter(Client.id == client_id).first()
    client_name = client.name if client else client_id
    risk = db.query(Risk).filter(Risk.id == risk_id, Risk.client_id == client_id).first()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")

    from services.risk_export import generate_single_risk_pdf, generate_single_risk_docx
    if format == "pdf":
        buf = generate_single_risk_pdf(client_name, risk)
        return StreamingResponse(
            buf,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=risk-{risk_id[:8]}.pdf"},
        )
    else:
        buf = generate_single_risk_docx(client_name, risk)
        return StreamingResponse(
            buf,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename=risk-{risk_id[:8]}.docx"},
        )


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


@router.post("/{risk_id}/reevaluate")
async def reevaluate_risk(
    client_id: str, risk_id: str, payload: ReevaluatePayload,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    """Re-run AI assessment on a formal Risk Register entry using updated measures checklist."""
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    risk = db.query(Risk).filter(Risk.id == risk_id, Risk.client_id == client_id).first()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")

    from api.routers.risk_proposals import _build_reevaluate_prompt, _call_llm_for_assessment

    measures_list = payload.measures
    prompt = _build_reevaluate_prompt(
        title=risk.title,
        description=risk.description or "",
        category=risk.category or "",
        wizard_data=payload.wizard_data,
        measures=measures_list,
        extra_context=getattr(payload, "extra_context", ""),
    )

    fallback = {
        "likelihood_factors": {
            "accessibility": payload.wizard_data.get("accessibility", risk.accessibility or 3),
            "discoverability": payload.wizard_data.get("discoverability", risk.discoverability or 3),
            "exploitability": payload.wizard_data.get("exploitability", risk.exploitability or 3),
            "authentication": payload.wizard_data.get("authentication_score", risk.authentication_score or 3),
            "repeatability": payload.wizard_data.get("repeatability", risk.repeatability or 3),
        },
        "consequence": payload.wizard_data.get("consequence", risk.consequence or 3),
        "workarounds": [],
        "overall_commentary": "Re-assessment complete.",
    }

    result = _call_llm_for_assessment(prompt, fallback)

    # Update the risk with new AI scores
    lf = result.get("likelihood_factors", {})
    factors = [
        lf.get("accessibility", risk.accessibility or 3),
        lf.get("discoverability", risk.discoverability or 3),
        lf.get("exploitability", risk.exploitability or 3),
        lf.get("authentication", risk.authentication_score or 3),
        lf.get("repeatability", risk.repeatability or 3),
    ]
    consequence = result.get("consequence", risk.consequence or 3)
    likelihood_avg = round(sum(factors) / len(factors), 2)
    matrix_score = round(consequence * likelihood_avg)

    risk.accessibility = factors[0]
    risk.discoverability = factors[1]
    risk.exploitability = factors[2]
    risk.authentication_score = factors[3]
    risk.repeatability = factors[4]
    risk.likelihood_avg = likelihood_avg
    risk.consequence = consequence
    risk.risk_matrix_score = matrix_score
    risk.residual_risk_level = _residual_label(matrix_score)
    risk.risk_level = _matrix_to_level(matrix_score)
    risk.likelihood = round(likelihood_avg * 2)
    risk.impact = consequence * 2
    risk.risk_score = round(risk.likelihood * risk.impact / 10, 2)
    risk.wizard_data_json = json.dumps(payload.wizard_data)
    risk.measures_json = json.dumps(measures_list)
    risk.ai_assessment_json = json.dumps(result)

    db.commit()
    db.refresh(risk)

    return {"risk": risk, "ai_result": result}


@router.delete("/{risk_id}", status_code=204)
async def delete_risk(client_id: str, risk_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    risk = db.query(Risk).filter(Risk.id == risk_id, Risk.client_id == client_id).first()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    db.delete(risk)
    db.commit()
