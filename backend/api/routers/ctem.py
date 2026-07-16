"""CTEM (Continuous Threat Exposure Management) program endpoints.

Each phase now has two AI-powered endpoints:
  GET  /{program_id}/phase-data/{phase}   — real platform metrics for that phase
  POST /{program_id}/ai-brief/{phase}     — LLM analysis grounded in that data, saved to DB

Manual notes fields are still writable — engineers and auditors can always
override or annotate AI output.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
import json
import logging

from api.models.models import (
    CTEMProgram, CTEMPhaseNote,
    Connector, ConnectorStatus,
    Scan, ScanStatus, Finding, Risk, RemediationAction,
)
from api.schemas.schemas import CTEMProgramCreate, CTEMProgramResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/clients/{client_id}/ctem", tags=["ctem"])

PHASES = ["scope", "discover", "prioritise", "validate", "mobilise"]

# SLA targets (hours)
_SLA = {"critical": 24, "high": 168, "medium": 720}


def _ensure_phases(db: Session, program: CTEMProgram):
    existing = {p.phase for p in program.phases}
    for phase in PHASES:
        if phase not in existing:
            db.add(CTEMPhaseNote(program_id=program.id, phase=phase))
    db.commit()
    db.refresh(program)


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.get("/", response_model=List[CTEMProgramResponse])
async def list_programs(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(CTEMProgram).filter(CTEMProgram.client_id == client_id).order_by(CTEMProgram.created_at.desc()).all()


@router.post("/", response_model=CTEMProgramResponse, dependencies=[Depends(require_editor_anywhere)])
async def create_program(
    client_id: str,
    payload: CTEMProgramCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    program = CTEMProgram(
        client_id=client_id,
        name=payload.name,
        description=payload.description,
        created_by=user.get("email") or user.get("preferred_username") or "",
    )
    db.add(program)
    db.commit()
    db.refresh(program)
    _ensure_phases(db, program)
    return program


@router.get("/{program_id}", response_model=CTEMProgramResponse)
async def get_program(client_id: str, program_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    p = db.query(CTEMProgram).filter(CTEMProgram.id == program_id, CTEMProgram.client_id == client_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="CTEM program not found")
    return p


@router.patch("/{program_id}/phases/{phase}", dependencies=[Depends(require_editor_anywhere)])
async def update_phase(
    client_id: str,
    program_id: str,
    phase: str,
    notes: str = None,
    completed: bool = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    if phase not in PHASES:
        raise HTTPException(status_code=400, detail=f"Phase must be one of {PHASES}")
    pn = db.query(CTEMPhaseNote).join(CTEMProgram).filter(
        CTEMPhaseNote.program_id == program_id,
        CTEMPhaseNote.phase == phase,
        CTEMProgram.client_id == client_id,
    ).first()
    if not pn:
        raise HTTPException(status_code=404, detail="Phase note not found")
    if notes is not None:
        pn.notes = notes
    if completed is not None:
        pn.completed = completed
        if completed and not pn.completed_at:
            pn.completed_at = datetime.now(timezone.utc)
            pn.completed_by = user.get("email") or ""
        if completed:
            program = pn.program
            current_idx = PHASES.index(phase)
            if current_idx + 1 < len(PHASES):
                program.current_phase = PHASES[current_idx + 1]
            else:
                program.status = "completed"
    db.commit()
    return {"updated": True, "phase": phase}


@router.delete("/{program_id}", dependencies=[Depends(require_editor_anywhere)])
async def delete_program(client_id: str, program_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    p = db.query(CTEMProgram).filter(CTEMProgram.id == program_id, CTEMProgram.client_id == client_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="CTEM program not found")
    db.delete(p)
    db.commit()
    return {"deleted": True}


# ── Phase data (live platform metrics) ────────────────────────────────────────

@router.get("/{program_id}/phase-data/{phase}")
async def get_phase_data(
    client_id: str,
    program_id: str,
    phase: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> Dict[str, Any]:
    if phase not in PHASES:
        raise HTTPException(status_code=400, detail=f"Phase must be one of {PHASES}")

    now = datetime.now(timezone.utc)

    if phase == "scope":
        connectors = db.query(Connector).filter(Connector.client_id == client_id).all()
        active = [c for c in connectors if c.status == ConnectorStatus.ACTIVE]
        return {
            "connectors_total": len(connectors),
            "connectors_active": len(active),
            "connectors": [
                {"id": c.id, "name": c.name, "type": c.connector_type, "status": c.status}
                for c in connectors
            ],
            "scan_types_available": list({c.connector_type for c in active}),
        }

    elif phase == "discover":
        scans = (
            db.query(Scan)
            .filter(Scan.client_id == client_id, Scan.status == ScanStatus.COMPLETED)
            .order_by(Scan.completed_at.desc())
            .limit(20)
            .all()
        )
        total_findings = (
            db.query(func.count(Finding.id))
            .join(Scan)
            .filter(Scan.client_id == client_id)
            .scalar() or 0
        )
        sev_counts: Dict[str, int] = {}
        for sev in ["critical", "high", "medium", "low", "info"]:
            sev_counts[sev] = (
                db.query(func.count(Finding.id))
                .join(Scan)
                .filter(Scan.client_id == client_id, Finding.severity == sev)
                .scalar() or 0
            )
        scan_types_run = list({s.scan_type for s in scans})
        last_scan_at = scans[0].completed_at.isoformat() if scans and scans[0].completed_at else None
        return {
            "scans_completed": len(scans),
            "last_scan_at": last_scan_at,
            "findings_total": total_findings,
            "findings_by_severity": sev_counts,
            "scan_types_run": scan_types_run,
            "recent_scans": [
                {
                    "type": s.scan_type,
                    "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                    "summary": s.summary or {},
                }
                for s in scans[:5]
            ],
        }

    elif phase == "prioritise":
        top_findings = (
            db.query(Finding)
            .join(Scan)
            .filter(Scan.client_id == client_id, Finding.status == "open", Finding.cvss_score.isnot(None))
            .order_by(Finding.cvss_score.desc())
            .limit(10)
            .all()
        )
        open_by_sev: Dict[str, int] = {}
        for sev in ["critical", "high", "medium", "low"]:
            open_by_sev[sev] = (
                db.query(func.count(Finding.id))
                .join(Scan)
                .filter(Scan.client_id == client_id, Finding.status == "open", Finding.severity == sev)
                .scalar() or 0
            )
        top_risks = (
            db.query(Risk)
            .filter(Risk.client_id == client_id, Risk.status == "open")
            .order_by(Risk.risk_score.desc())
            .limit(5)
            .all()
        )
        return {
            "open_findings_total": sum(open_by_sev.values()),
            "open_by_severity": open_by_sev,
            "top_findings_by_cvss": [
                {"title": f.title, "severity": f.severity, "cvss": f.cvss_score, "cve": f.cve_id, "resource": f.resource_id}
                for f in top_findings
            ],
            "top_risks": [
                {"title": r.title, "score": r.risk_score, "level": r.risk_level, "category": r.category}
                for r in top_risks
            ],
        }

    elif phase == "validate":
        status_counts: Dict[str, int] = {}
        for s in ["open", "in_progress", "remediated", "false_positive", "accepted"]:
            status_counts[s] = (
                db.query(func.count(Finding.id))
                .join(Scan)
                .filter(Scan.client_id == client_id, Finding.status == s)
                .scalar() or 0
            )
        try:
            from api.models.models import VAPTReport
            vapt_count = db.query(func.count(VAPTReport.id)).filter(VAPTReport.client_id == client_id).scalar() or 0
        except Exception:
            vapt_count = 0
        total = sum(status_counts.values())
        return {
            "finding_statuses": status_counts,
            "vapt_reports": vapt_count,
            "findings_total": total,
            "confirmed_pct": round((status_counts.get("in_progress", 0) + status_counts.get("remediated", 0)) / max(total, 1) * 100),
        }

    elif phase == "mobilise":
        actions = db.query(RemediationAction).filter(RemediationAction.client_id == client_id).all()
        action_statuses: Dict[str, int] = {}
        for a in actions:
            action_statuses[a.status] = action_statuses.get(a.status, 0) + 1

        sla_breaches: Dict[str, int] = {}
        for sev, hours in _SLA.items():
            sla_breaches[sev] = (
                db.query(func.count(Finding.id))
                .join(Scan)
                .filter(
                    Scan.client_id == client_id,
                    Finding.severity == sev,
                    Finding.status == "open",
                    Finding.created_at < now - timedelta(hours=hours),
                )
                .scalar() or 0
            )

        remediated_this_month = (
            db.query(func.count(Finding.id))
            .join(Scan)
            .filter(
                Scan.client_id == client_id,
                Finding.status == "remediated",
                Finding.remediated_at >= now - timedelta(days=30),
            )
            .scalar() or 0
        )
        return {
            "remediation_actions": action_statuses,
            "actions_total": len(actions),
            "sla_breaches": sla_breaches,
            "remediated_last_30d": remediated_this_month,
        }

    return {}


# ── AI brief (LLM analysis saved to phase) ────────────────────────────────────

@router.post("/{program_id}/ai-brief/{phase}", dependencies=[Depends(require_editor_anywhere)])
async def generate_ai_brief(
    client_id: str,
    program_id: str,
    phase: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> Dict[str, Any]:
    if phase not in PHASES:
        raise HTTPException(status_code=400, detail=f"Phase must be one of {PHASES}")

    pn = db.query(CTEMPhaseNote).join(CTEMProgram).filter(
        CTEMPhaseNote.program_id == program_id,
        CTEMPhaseNote.phase == phase,
        CTEMProgram.client_id == client_id,
    ).first()
    if not pn:
        raise HTTPException(status_code=404, detail="Phase note not found")

    # Fetch live data for the prompt
    from fastapi import Request
    phase_data = await get_phase_data.__wrapped__(client_id, program_id, phase, db, _) if hasattr(get_phase_data, "__wrapped__") else {}
    # Direct data fetch (avoids re-routing through FastAPI)
    phase_data = _fetch_phase_data_direct(client_id, phase, db)

    program = pn.program
    prompt = _build_brief_prompt(phase, phase_data, program.name, program.description)

    try:
        from core.ai_providers import get_llm
        llm = get_llm()
        from langchain_core.messages import HumanMessage, SystemMessage
        messages = [
            SystemMessage(content=(
                "You are a senior cybersecurity consultant writing a concise, actionable CTEM phase analysis. "
                "Ground your analysis strictly in the data provided. Use bullet points and clear headings. "
                "Be direct and specific — no generic advice. Limit to 400 words."
            )),
            HumanMessage(content=prompt),
        ]
        result = llm.invoke(messages)
        brief_text = result.content if hasattr(result, "content") else str(result)
    except Exception as exc:
        logger.warning("AI brief generation failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"AI provider unavailable: {exc}")

    pn.ai_brief = brief_text
    pn.ai_brief_generated_at = datetime.now(timezone.utc)
    db.commit()

    return {"brief": brief_text, "generated_at": pn.ai_brief_generated_at.isoformat()}


def _fetch_phase_data_direct(client_id: str, phase: str, db: Session) -> Dict[str, Any]:
    """Same logic as get_phase_data but called synchronously without request routing."""
    now = datetime.now(timezone.utc)

    if phase == "scope":
        connectors = db.query(Connector).filter(Connector.client_id == client_id).all()
        active = [c for c in connectors if c.status == ConnectorStatus.ACTIVE]
        return {
            "connectors_total": len(connectors),
            "connectors_active": len(active),
            "connectors": [{"name": c.name, "type": c.connector_type, "status": c.status} for c in connectors],
            "scan_types_available": list({c.connector_type for c in active}),
        }

    elif phase == "discover":
        scans = (
            db.query(Scan)
            .filter(Scan.client_id == client_id, Scan.status == ScanStatus.COMPLETED)
            .order_by(Scan.completed_at.desc())
            .limit(20)
            .all()
        )
        total = db.query(func.count(Finding.id)).join(Scan).filter(Scan.client_id == client_id).scalar() or 0
        sev: Dict[str, int] = {}
        for s in ["critical", "high", "medium", "low", "info"]:
            sev[s] = db.query(func.count(Finding.id)).join(Scan).filter(Scan.client_id == client_id, Finding.severity == s).scalar() or 0
        return {
            "scans_completed": len(scans),
            "findings_total": total,
            "findings_by_severity": sev,
            "scan_types_run": list({s.scan_type for s in scans}),
        }

    elif phase == "prioritise":
        top = (
            db.query(Finding)
            .join(Scan)
            .filter(Scan.client_id == client_id, Finding.status == "open", Finding.cvss_score.isnot(None))
            .order_by(Finding.cvss_score.desc())
            .limit(10)
            .all()
        )
        open_sev: Dict[str, int] = {}
        for s in ["critical", "high", "medium", "low"]:
            open_sev[s] = db.query(func.count(Finding.id)).join(Scan).filter(Scan.client_id == client_id, Finding.status == "open", Finding.severity == s).scalar() or 0
        return {
            "open_findings_total": sum(open_sev.values()),
            "open_by_severity": open_sev,
            "top_findings_by_cvss": [{"title": f.title, "severity": f.severity, "cvss": f.cvss_score, "cve": f.cve_id} for f in top],
        }

    elif phase == "validate":
        sc: Dict[str, int] = {}
        for s in ["open", "in_progress", "remediated", "false_positive", "accepted"]:
            sc[s] = db.query(func.count(Finding.id)).join(Scan).filter(Scan.client_id == client_id, Finding.status == s).scalar() or 0
        try:
            from api.models.models import VAPTReport
            vapt = db.query(func.count(VAPTReport.id)).filter(VAPTReport.client_id == client_id).scalar() or 0
        except Exception:
            vapt = 0
        return {"finding_statuses": sc, "vapt_reports": vapt}

    elif phase == "mobilise":
        actions = db.query(RemediationAction).filter(RemediationAction.client_id == client_id).all()
        ast: Dict[str, int] = {}
        for a in actions:
            ast[a.status] = ast.get(a.status, 0) + 1
        sla: Dict[str, int] = {}
        for sev, hours in _SLA.items():
            sla[sev] = db.query(func.count(Finding.id)).join(Scan).filter(
                Scan.client_id == client_id, Finding.severity == sev,
                Finding.status == "open", Finding.created_at < now - timedelta(hours=hours),
            ).scalar() or 0
        return {"remediation_actions": ast, "actions_total": len(actions), "sla_breaches": sla}

    return {}


def _build_brief_prompt(phase: str, data: Dict[str, Any], program_name: str, program_desc: str | None) -> str:
    desc_line = f"Program description: {program_desc}" if program_desc else ""
    data_str = json.dumps(data, indent=2, default=str)

    PHASE_INSTRUCTIONS = {
        "scope": (
            "Write a Scope phase brief. Based on the connectors and scan types available, recommend:\n"
            "1. Which assets and systems should be in scope for this CTEM cycle\n"
            "2. Any coverage gaps (connector types missing)\n"
            "3. Recommended scope statement for the program\n"
        ),
        "discover": (
            "Write a Discover phase brief. Based on the scan results and finding counts:\n"
            "1. Summarise the current attack surface footprint\n"
            "2. Identify coverage gaps (scan types not run, severity distribution anomalies)\n"
            "3. Recommend specific additional scans to close gaps\n"
        ),
        "prioritise": (
            "Write a Prioritise phase brief. Based on the open findings and risk scores:\n"
            "1. Identify the top 5 priority items with reasoning (CVSS + severity + business context)\n"
            "2. Flag any critical/high findings that need immediate attention\n"
            "3. Recommend a prioritised remediation order\n"
        ),
        "validate": (
            "Write a Validate phase brief. Based on the finding statuses and VAPT coverage:\n"
            "1. Assess what percentage of findings have been confirmed vs. machine-detected only\n"
            "2. Identify which findings need manual validation (VAPT/pen test)\n"
            "3. Recommend specific validation activities\n"
        ),
        "mobilise": (
            "Write a Mobilise phase brief. Based on the remediation action statuses and SLA breaches:\n"
            "1. Call out any SLA breaches with urgency (critical = 24h, high = 7d, medium = 30d)\n"
            "2. Assess remediation velocity and whether the team is on track\n"
            "3. Recommend specific next actions to accelerate closure\n"
        ),
    }

    instructions = PHASE_INSTRUCTIONS.get(phase, "Provide a phase analysis based on the data below.")

    return f"""CTEM Program: {program_name}
{desc_line}
Phase: {phase.upper()}

Platform data for this phase:
{data_str}

{instructions}
Be specific to the numbers above. Do not invent data not present in the platform output."""
