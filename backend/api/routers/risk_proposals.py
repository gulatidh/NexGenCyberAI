"""Risk Proposal staging router — proposals land here before formal evaluation."""
import json
from datetime import datetime, timezone
from typing import Optional, List, Any, Dict
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.models.models import Risk, RiskProposal, RiskLevel, Client
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


def _parse_json_safe(val: Any) -> Any:
    if not val:
        return None
    if isinstance(val, (dict, list)):
        return val
    try:
        return json.loads(val)
    except Exception:
        return None


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
    # New fields for rich wizard data
    wizard_data: Optional[Dict[str, Any]] = None
    measures: Optional[List[Dict[str, Any]]] = None
    ai_assessment: Optional[Dict[str, Any]] = None


class MeasureItem(BaseModel):
    id: str
    text: str
    status: str = "pending"  # pending | in_place | not_possible
    category: Optional[str] = None


class ReevaluatePayload(BaseModel):
    wizard_data: Dict[str, Any]
    measures: List[MeasureItem] = []
    extra_context: str = ""


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


def _build_ai_draft_prompt(title: str, description: str, category: str, risk_type: str) -> str:
    return f"""You are a cybersecurity risk analyst specialising in GCC IM8 and ISO 27001 risk assessments.

A risk proposal has been submitted. Perform a comprehensive initial risk assessment and return a structured pre-fill for an 8-step risk evaluation wizard.

Risk Title: {title}
Description: {description or '(none provided)'}
Risk Area / Category: {category or 'General'}
Risk Type: {risk_type or 'Security'}

You must score each likelihood factor on a 1-5 scale:
- Accessibility: 1=physically isolated, 5=fully open/no restriction
- Discoverability: 1=cannot find it, 5=indexed/trivially discoverable
- Exploitability: 1=no exploit exists, 5=automated exploit tool exists
- Authentication: 1=strong MFA+certs, 5=no authentication
- Repeatability: 1=one-time only, 5=always repeatable/deterministic
- Consequence: 1=negligible, 5=catastrophic/existential

Suggest 5-8 specific security measures (controls) to mitigate or manage this risk.

Respond with ONLY valid JSON (no markdown fences):
{{
  "basic_info": {{
    "scenario": "<2-3 sentence description of the risk scenario>",
    "threat": "<the specific threat actor or threat event>",
    "risk_area": "{category or 'General'}",
    "risk_type": "{risk_type or 'Security'}"
  }},
  "likelihood_factors": {{
    "accessibility": <1-5>,
    "accessibility_rationale": "<why this score>",
    "discoverability": <1-5>,
    "discoverability_rationale": "<why this score>",
    "exploitability": <1-5>,
    "exploitability_rationale": "<why this score>",
    "authentication": <1-5>,
    "authentication_rationale": "<why this score>",
    "repeatability": <1-5>,
    "repeatability_rationale": "<why this score>"
  }},
  "consequence": <1-5>,
  "consequence_rationale": "<why this consequence score>",
  "treatment": "<Avoid|Mitigate|Transfer|Accept>",
  "treatment_rationale": "<why this treatment>",
  "measures": [
    {{"id": "M1", "text": "<specific control measure>", "category": "preventive"}},
    {{"id": "M2", "text": "<specific control measure>", "category": "detective"}},
    {{"id": "M3", "text": "<specific control measure>", "category": "corrective"}},
    {{"id": "M4", "text": "<specific control measure>", "category": "preventive"}},
    {{"id": "M5", "text": "<specific control measure>", "category": "preventive"}}
  ],
  "overall_commentary": "<2-3 sentence overall risk narrative and recommendation>"
}}"""


def _build_reevaluate_prompt(
    title: str, description: str, category: str,
    wizard_data: dict, measures: list, extra_context: str = ""
) -> str:
    in_place = [m for m in measures if m.get("status") == "in_place"]
    not_possible = [m for m in measures if m.get("status") == "not_possible"]
    pending = [m for m in measures if m.get("status") == "pending"]

    measures_text = "\n".join([
        f"  [{m.get('status','pending').upper()}] {m.get('id')}: {m.get('text')}"
        for m in measures
    ]) or "  (none)"

    context_block = f"\nAdditional context provided by analyst:\n{extra_context.strip()}\n" if extra_context.strip() else ""

    return f"""You are a cybersecurity risk analyst specialising in GCC IM8 and ISO 27001 risk assessments.

Re-evaluate a risk that has been partially assessed. The user has adjusted the likelihood factor scores and updated the security measures checklist. Re-assess all factors considering the implemented controls and any additional context provided.

Risk: {title}
Description: {description or '(none)'}
Category: {category or 'General'}
{context_block}
Current likelihood factor values (user-adjusted, scale 1-5 where 5 is worst):
- Accessibility:    {wizard_data.get('accessibility', 3)}/5
- Discoverability:  {wizard_data.get('discoverability', 3)}/5
- Exploitability:   {wizard_data.get('exploitability', 3)}/5
- Authentication:   {wizard_data.get('authentication_score', 3)}/5 (5=no auth, 1=strong MFA)
- Repeatability:    {wizard_data.get('repeatability', 3)}/5
- Consequence:      {wizard_data.get('consequence', 3)}/5
- Treatment intent: {wizard_data.get('treatment_option', 'mitigate')}

Security measures checklist:
{measures_text}

Summary:
- {len(in_place)} measures IN PLACE (already implemented — these should reduce relevant factor scores)
- {len(not_possible)} measures NOT POSSIBLE (need workaround alternatives)
- {len(pending)} measures PENDING (planned but not yet implemented)

Instructions:
1. Re-score each likelihood factor considering IN PLACE measures AND any extra context. If context reveals mitigating factors (e.g. components on same host, air-gapped network), reduce scores accordingly. If it reveals amplifying factors (e.g. internet-facing, shared credentials), increase scores.
2. For each NOT POSSIBLE measure, suggest a specific, practical alternative control.
3. Update the overall commentary to reflect the analyst's context and current control state.

Respond with ONLY valid JSON (no markdown fences):
{{
  "basic_info": {{
    "scenario": "<updated scenario>",
    "threat": "<updated threat>",
    "risk_area": "{category or 'General'}",
    "risk_type": "Security"
  }},
  "likelihood_factors": {{
    "accessibility": <1-5>,
    "accessibility_rationale": "<updated rationale>",
    "discoverability": <1-5>,
    "discoverability_rationale": "<updated rationale>",
    "exploitability": <1-5>,
    "exploitability_rationale": "<updated rationale>",
    "authentication": <1-5>,
    "authentication_rationale": "<updated rationale>",
    "repeatability": <1-5>,
    "repeatability_rationale": "<updated rationale>"
  }},
  "consequence": <1-5>,
  "consequence_rationale": "<updated rationale>",
  "treatment": "<Avoid|Mitigate|Transfer|Accept>",
  "treatment_rationale": "<updated rationale>",
  "measures": {json.dumps(measures)},
  "workarounds": [
    {{"measure_id": "<id of not_possible measure>", "alternative": "<specific workaround control>"}}
  ],
  "overall_commentary": "<updated 2-3 sentence commentary reflecting current state and residual risk>"
}}"""


def _call_llm_for_assessment(prompt: str, fallback: dict) -> dict:
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
        return json.loads(content)
    except Exception:
        return fallback


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


@router.post("/{proposal_id}/ai-draft")
async def ai_draft_proposal(
    client_id: str, proposal_id: str,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    """Generate structured AI pre-fill for all 8 wizard steps from proposal description only."""
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    p = db.query(RiskProposal).filter(
        RiskProposal.id == proposal_id, RiskProposal.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")

    prompt = _build_ai_draft_prompt(
        title=p.title,
        description=p.description or "",
        category=p.category or "",
        risk_type=p.risk_type or "Security",
    )

    fallback = {
        "basic_info": {
            "scenario": p.description or p.title,
            "threat": "Threat actor exploiting this vulnerability",
            "risk_area": p.category or "General",
            "risk_type": p.risk_type or "Security",
        },
        "likelihood_factors": {
            "accessibility": 3, "accessibility_rationale": "Moderate access controls in place",
            "discoverability": 3, "discoverability_rationale": "Requires standard scanning tools",
            "exploitability": 3, "exploitability_rationale": "Moderate skill required",
            "authentication": 3, "authentication_rationale": "Password-based authentication",
            "repeatability": 3, "repeatability_rationale": "Sometimes repeatable",
        },
        "consequence": 3,
        "consequence_rationale": "Moderate business impact expected",
        "treatment": "Mitigate",
        "treatment_rationale": "Risk can be reduced through targeted controls",
        "measures": [
            {"id": "M1", "text": "Implement access control review", "category": "preventive"},
            {"id": "M2", "text": "Enable security monitoring and alerting", "category": "detective"},
            {"id": "M3", "text": "Conduct vulnerability assessment", "category": "preventive"},
            {"id": "M4", "text": "Establish incident response procedure", "category": "corrective"},
            {"id": "M5", "text": "Regular security training for staff", "category": "preventive"},
        ],
        "overall_commentary": f"This risk requires assessment and appropriate controls. Score: medium.",
    }

    result = _call_llm_for_assessment(prompt, fallback)

    # Persist draft so re-opening the wizard restores the last AI result
    p.ai_draft_json = json.dumps(result)
    db.commit()

    return result


@router.post("/{proposal_id}/reevaluate")
async def reevaluate_proposal(
    client_id: str, proposal_id: str, payload: ReevaluatePayload,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    """Re-run AI assessment using user-adjusted wizard data + measures checklist statuses."""
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    p = db.query(RiskProposal).filter(
        RiskProposal.id == proposal_id, RiskProposal.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")

    measures_list = [m.model_dump() for m in payload.measures]
    prompt = _build_reevaluate_prompt(
        title=p.title,
        description=p.description or "",
        category=p.category or "",
        wizard_data=payload.wizard_data,
        measures=measures_list,
        extra_context=payload.extra_context,
    )

    fallback = {
        "basic_info": {"scenario": p.description or p.title, "threat": "Threat actor"},
        "likelihood_factors": {
            "accessibility": payload.wizard_data.get("accessibility", 3), "accessibility_rationale": "Based on current controls",
            "discoverability": payload.wizard_data.get("discoverability", 3), "discoverability_rationale": "Based on current controls",
            "exploitability": payload.wizard_data.get("exploitability", 3), "exploitability_rationale": "Based on current controls",
            "authentication": payload.wizard_data.get("authentication_score", 3), "authentication_rationale": "Based on current controls",
            "repeatability": payload.wizard_data.get("repeatability", 3), "repeatability_rationale": "Based on current controls",
        },
        "consequence": payload.wizard_data.get("consequence", 3),
        "consequence_rationale": "Based on current assessment",
        "treatment": payload.wizard_data.get("treatment_option", "Mitigate"),
        "treatment_rationale": "Maintain current treatment strategy",
        "measures": measures_list,
        "workarounds": [],
        "overall_commentary": "Re-assessment complete. Review implemented controls for effectiveness.",
    }

    result = _call_llm_for_assessment(prompt, fallback)

    # Persist the re-assessed result and measures back to the proposal
    p.ai_draft_json = json.dumps(result)
    # Merge measure statuses into result measures list
    status_map = {m.id: m.status for m in payload.measures}
    if result.get("measures"):
        for m in result["measures"]:
            if m.get("id") in status_map:
                m["status"] = status_map[m["id"]]
    db.commit()

    return result


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
        # Store full wizard data, measures and AI assessment
        wizard_data_json=json.dumps(payload.wizard_data) if payload.wizard_data else None,
        measures_json=json.dumps(payload.measures) if payload.measures else None,
        ai_assessment_json=json.dumps(payload.ai_assessment) if payload.ai_assessment else None,
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

    fallback = {
        "summary": f"Risk score: {matrix_score}/25 ({label}). Manual review recommended.",
        "recommended_treatment": "mitigate",
        "key_controls": ["Access Control (A.9)", "Vulnerability Management (A.12)", "Incident Management (A.16)"],
        "mitigation_steps": ["Implement compensating controls", "Monitor and review regularly", "Document treatment decision"],
        "residual_risk_after_controls": f"Target: reduce from {label} after controls implementation.",
    }

    return _call_llm_for_assessment(prompt, fallback)
