"""Risk Proposal staging router — proposals land here before formal evaluation."""
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.models.models import Risk, RiskProposal, RiskLevel
from db.database import get_db
from core.security import get_current_user
from core.authz import require_scoped_role, AccessRole, AccessScope
from core.ai_providers import get_llm

router = APIRouter(prefix="/clients/{client_id}/risk-proposals", tags=["risk-proposals"])

_RISK_LEVEL_FROM_MATRIX = {
    range(1, 5):   RiskLevel.LOW,
    range(5, 10):  RiskLevel.MEDIUM,
    range(10, 13): RiskLevel.MEDIUM,
    range(13, 21): RiskLevel.HIGH,
    range(21, 26): RiskLevel.CRITICAL,
}


def _matrix_to_level(score: int) -> RiskLevel:
    for rng, level in _RISK_LEVEL_FROM_MATRIX.items():
        if score in rng:
            return level
    return RiskLevel.HIGH


def _residual_label(score: int) -> str:
    if score <= 4:
        return "low"
    if score <= 9:
        return "medium"
    if score <= 12:
        return "medium_high"
    if score <= 20:
        return "high"
    return "critical"


class ProposalCreate(BaseModel):
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    risk_type: Optional[str] = None
    source: Optional[str] = "manual"
    source_finding_id: Optional[str] = None
    source_agent_run_id: Optional[str] = None
    notes: Optional[str] = None


class ProposalUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    risk_type: Optional[str] = None
    notes: Optional[str] = None


class EvaluatePayload(BaseModel):
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    risk_area: Optional[str] = None
    risk_type_gcim8: Optional[str] = None
    accessibility: int = 3
    discoverability: int = 3
    exploitability: int = 3
    authentication_score: int = 3
    repeatability: int = 3
    consequence: int = 3
    treatment_option: Optional[str] = "mitigate"
    owner: Optional[str] = None
    assignee_email: Optional[str] = None
    due_date: Optional[str] = None
    mitigation_plan: Optional[str] = None


class AnalyseRequest(BaseModel):
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    risk_type: Optional[str] = None
    accessibility: int = 3
    discoverability: int = 3
    exploitability: int = 3
    authentication_score: int = 3
    repeatability: int = 3
    consequence: int = 3


def _get_stats(client_id: str, db: Session) -> dict:
    qs = db.query(RiskProposal).filter(RiskProposal.client_id == client_id)
    return {
        "pending_count": qs.filter(RiskProposal.status == "pending").count(),
        "archived_count": qs.filter(RiskProposal.status == "archived").count(),
        "dismissed_count": qs.filter(RiskProposal.status == "dismissed").count(),
        "evaluated_count": qs.filter(RiskProposal.status == "evaluated").count(),
    }


@router.get("/")
async def list_proposals(
    client_id: str,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    q = db.query(RiskProposal).filter(RiskProposal.client_id == client_id)
    if status:
        q = q.filter(RiskProposal.status == status)
    proposals = q.order_by(RiskProposal.created_at.desc()).all()
    return {"proposals": proposals, "stats": _get_stats(client_id, db)}


@router.post("/", status_code=201)
async def create_proposal(
    client_id: str,
    payload: ProposalCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    proposal = RiskProposal(client_id=client_id, **payload.model_dump())
    db.add(proposal)
    db.commit()
    db.refresh(proposal)
    return proposal


@router.get("/{proposal_id}")
async def get_proposal(
    client_id: str, proposal_id: str,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    p = db.query(RiskProposal).filter(
        RiskProposal.id == proposal_id, RiskProposal.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return p


@router.patch("/{proposal_id}")
async def update_proposal(
    client_id: str, proposal_id: str, payload: ProposalUpdate,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    p = db.query(RiskProposal).filter(
        RiskProposal.id == proposal_id, RiskProposal.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    for k, v in payload.model_dump(exclude_none=True).items():
        setattr(p, k, v)
    db.commit()
    db.refresh(p)
    return p


@router.delete("/{proposal_id}", status_code=204)
async def delete_proposal(
    client_id: str, proposal_id: str,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    p = db.query(RiskProposal).filter(
        RiskProposal.id == proposal_id, RiskProposal.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    db.delete(p)
    db.commit()


@router.post("/{proposal_id}/dismiss")
async def dismiss_proposal(
    client_id: str, proposal_id: str,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    p = db.query(RiskProposal).filter(
        RiskProposal.id == proposal_id, RiskProposal.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    p.status = "dismissed"
    p.dismissed_at = datetime.now(timezone.utc)
    p.archived_at = None
    db.commit()
    db.refresh(p)
    return p


@router.post("/{proposal_id}/archive")
async def archive_proposal(
    client_id: str, proposal_id: str,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    p = db.query(RiskProposal).filter(
        RiskProposal.id == proposal_id, RiskProposal.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    p.status = "archived"
    p.archived_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(p)
    return p


@router.post("/{proposal_id}/restore")
async def restore_proposal(
    client_id: str, proposal_id: str,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    p = db.query(RiskProposal).filter(
        RiskProposal.id == proposal_id, RiskProposal.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    p.status = "pending"
    p.dismissed_at = None
    p.archived_at = None
    db.commit()
    db.refresh(p)
    return p


@router.post("/{proposal_id}/evaluate")
async def evaluate_proposal(
    client_id: str, proposal_id: str, payload: EvaluatePayload,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    p = db.query(RiskProposal).filter(
        RiskProposal.id == proposal_id, RiskProposal.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")

    factors = [
        payload.accessibility, payload.discoverability, payload.exploitability,
        payload.authentication_score, payload.repeatability,
    ]
    likelihood_avg = round(sum(factors) / len(factors), 2)
    risk_matrix_score = round(payload.consequence * likelihood_avg)
    risk_level = _matrix_to_level(risk_matrix_score)
    residual = _residual_label(risk_matrix_score)

    # legacy likelihood/impact mapping (1-10 scale)
    legacy_likelihood = round(likelihood_avg * 2)
    legacy_impact = payload.consequence * 2

    risk = Risk(
        client_id=client_id,
        title=payload.title,
        description=payload.description,
        risk_level=risk_level,
        likelihood=legacy_likelihood,
        impact=legacy_impact,
        risk_score=round(legacy_likelihood * legacy_impact / 10, 2),
        category=payload.category or payload.risk_area,
        owner=payload.owner,
        assignee_email=payload.assignee_email,
        mitigation_plan=payload.mitigation_plan,
        status="open",
        # GCC IM8 structured fields
        risk_area=payload.risk_area or payload.category,
        risk_type_gcim8=payload.risk_type_gcim8,
        accessibility=payload.accessibility,
        discoverability=payload.discoverability,
        exploitability=payload.exploitability,
        authentication_score=payload.authentication_score,
        repeatability=payload.repeatability,
        likelihood_avg=likelihood_avg,
        consequence=payload.consequence,
        risk_matrix_score=risk_matrix_score,
        residual_risk_level=residual,
        treatment_option=payload.treatment_option,
        proposal_id=proposal_id,
    )
    db.add(risk)

    p.status = "evaluated"
    p.evaluated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(risk)
    db.refresh(p)
    p.risk_id = risk.id
    db.commit()

    return {"proposal": p, "risk": risk}


@router.post("/analyse")
async def analyse_proposal(
    client_id: str, payload: AnalyseRequest,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    likelihood_avg = round(
        (payload.accessibility + payload.discoverability + payload.exploitability +
         payload.authentication_score + payload.repeatability) / 5, 2
    )
    matrix_score = round(payload.consequence * likelihood_avg)
    label = _residual_label(matrix_score)

    prompt = f"""You are a cybersecurity risk analyst specialising in GCC IM8 and ISO 27001 risk assessments.

Risk: {payload.title}
Description: {payload.description or '(none)'}
Category: {payload.category or payload.risk_type or 'General'}
Risk Type: {payload.risk_type or 'Security'}

Likelihood Factors (1=lowest, 5=highest):
- Accessibility: {payload.accessibility}/5
- Discoverability: {payload.discoverability}/5
- Exploitability: {payload.exploitability}/5
- Authentication Strength: {payload.authentication_score}/5 (5=none, 1=strong MFA)
- Repeatability: {payload.repeatability}/5
Average Likelihood: {likelihood_avg}/5
Consequence: {payload.consequence}/5
Risk Matrix Score: {matrix_score}/25 ({label.upper()})

Respond with ONLY valid JSON (no markdown fences):
{{
  "summary": "<2-3 sentence risk narrative>",
  "recommended_treatment": "<avoid|mitigate|transfer|accept> with brief rationale",
  "key_controls": ["<ISO 27001 or GCC IM8 control 1>", "<control 2>", "<control 3>"],
  "mitigation_steps": ["<step 1>", "<step 2>", "<step 3>"],
  "residual_risk_after_controls": "<description of expected residual risk level>"
}}"""

    try:
        llm = get_llm()
        resp = llm.invoke(prompt)
        content = resp.content if hasattr(resp, "content") else str(resp)
        content = content.strip()
        if content.startswith("```"):
            parts = content.split("```")
            content = parts[1] if len(parts) > 1 else content
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()
        import json
        return json.loads(content)
    except Exception as exc:
        return {
            "summary": f"Risk score: {matrix_score}/25 ({label}). Manual review recommended.",
            "recommended_treatment": "mitigate",
            "key_controls": ["Access Control (A.9)", "Vulnerability Management (A.12)", "Incident Management (A.16)"],
            "mitigation_steps": ["Implement compensating controls", "Monitor and review regularly", "Document treatment decision"],
            "residual_risk_after_controls": f"Target: reduce from {label} after controls implementation.",
        }
