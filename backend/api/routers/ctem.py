"""CTEM (Continuous Threat Exposure Management) program endpoints.

Phase structure:
  Scope      → asset tagging (in-scope / out-of-scope / crown-jewel)
  Discover   → findings filtered to scoped assets, grouped by exposure category
  Prioritise → AI top-5 + analyst add/remove/reorder
  Validate   → validation method table + notable findings (analyst-editable)
  Mobilise   → owner team table + blockers (analyst-editable)

Every phase stores structured data in phase_data_json (JSON blob on CTEMPhaseNote).
AI briefs are written by the LLM then fully editable by the analyst.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any, Optional
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

_SLA = {"critical": 24, "high": 168, "medium": 720}

# Maps resource_type → human-readable exposure category
EXPOSURE_CATEGORY_MAP = {
    "code_file":        "SAST / Code Security",
    "web_endpoint":     "External Attack Surface (EASM)",
    "cloud_resource":   "Cloud Security Posture (CSPM)",
    "host":             "Infrastructure / Internal",
    "identity":         "Identity & Entitlement (IdEM)",
    "dependency":       "Third-Party / Supply Chain",
    "container":        "Container & Image Security",
    "network":          "Network Security",
}


def _exposure_category(resource_type: Optional[str]) -> str:
    if not resource_type:
        return "Uncategorised"
    rt = resource_type.lower()
    for key, label in EXPOSURE_CATEGORY_MAP.items():
        if key in rt:
            return label
    return resource_type.replace("_", " ").title()


def _discover_assets(db: Session, client_id: str) -> List[Dict]:
    """Query findings for the client and return a list of asset dicts for scope pre-seeding."""
    # Primary: findings with a non-empty resource_id
    rows = (
        db.query(Finding.resource_id, Finding.resource_type, func.count(Finding.id).label("cnt"))
        .join(Scan)
        .filter(
            Scan.client_id == client_id,
            Finding.resource_id.isnot(None),
            Finding.resource_id != "",
        )
        .group_by(Finding.resource_id, Finding.resource_type)
        .order_by(func.count(Finding.id).desc())
        .limit(200)
        .all()
    )
    # Fallback: group by resource_type when resource_ids are absent
    if not rows:
        rows = (
            db.query(Finding.resource_type, Finding.resource_type, func.count(Finding.id).label("cnt"))
            .join(Scan)
            .filter(Scan.client_id == client_id, Finding.resource_type.isnot(None), Finding.resource_type != "")
            .group_by(Finding.resource_type)
            .order_by(func.count(Finding.id).desc())
            .limit(50)
            .all()
        )
    assets = []
    for resource_id, resource_type, cnt in rows:
        rid = resource_id or resource_type or "unknown"
        assets.append({
            "resource_id": rid,
            "resource_type": resource_type or "unknown",
            "display_name": rid,
            "exposure_category": _exposure_category(resource_type),
            "finding_count": cnt,
            "scope_status": "untagged",
            "notes": "",
        })
    return assets


def _ensure_phases(db: Session, program: CTEMProgram):
    existing = {p.phase for p in program.phases}
    needs_asset_seed = "scope" not in existing
    for phase in PHASES:
        if phase not in existing:
            db.add(CTEMPhaseNote(program_id=program.id, phase=phase))
    db.commit()
    db.refresh(program)
    # Auto-seed scope assets from existing findings so the analyst sees something immediately
    if needs_asset_seed:
        scope_pn = next((p for p in program.phases if p.phase == "scope"), None)
        if scope_pn:
            assets = _discover_assets(db, program.client_id)
            scope_pn.phase_data_json = {"assets": assets}
            db.commit()


def _get_phase_note(db: Session, client_id: str, program_id: str, phase: str) -> CTEMPhaseNote:
    pn = (
        db.query(CTEMPhaseNote)
        .join(CTEMProgram)
        .filter(
            CTEMPhaseNote.program_id == program_id,
            CTEMPhaseNote.phase == phase,
            CTEMProgram.client_id == client_id,
        )
        .first()
    )
    if not pn:
        # Phase notes missing — program was created before _ensure_phases existed.
        # Auto-create them now so old programs work without re-creating.
        program = (
            db.query(CTEMProgram)
            .filter(CTEMProgram.id == program_id, CTEMProgram.client_id == client_id)
            .first()
        )
        if not program:
            raise HTTPException(status_code=404, detail="CTEM program not found")
        _ensure_phases(db, program)
        pn = db.query(CTEMPhaseNote).filter(
            CTEMPhaseNote.program_id == program_id,
            CTEMPhaseNote.phase == phase,
        ).first()
        if not pn:
            raise HTTPException(status_code=500, detail="Failed to create phase note")
    return pn


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.get("/", response_model=List[CTEMProgramResponse])
async def list_programs(
    client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)
):
    return (
        db.query(CTEMProgram)
        .filter(CTEMProgram.client_id == client_id)
        .order_by(CTEMProgram.created_at.desc())
        .all()
    )


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
async def get_program(
    client_id: str, program_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)
):
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
    pn = _get_phase_note(db, client_id, program_id, phase)
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
async def delete_program(
    client_id: str, program_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)
):
    p = db.query(CTEMProgram).filter(CTEMProgram.id == program_id, CTEMProgram.client_id == client_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="CTEM program not found")
    db.delete(p)
    db.commit()
    return {"deleted": True}


# ── Save analyst phase data (generic for all phases) ──────────────────────────

@router.get("/{program_id}/phase-data/{phase}")
async def get_phase_data(
    client_id: str,
    program_id: str,
    phase: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> Dict[str, Any]:
    """Return stored structured data for any phase."""
    if phase not in PHASES:
        raise HTTPException(status_code=400, detail=f"Phase must be one of {PHASES}")
    pn = _get_phase_note(db, client_id, program_id, phase)
    return pn.phase_data_json or {}


@router.put("/{program_id}/phase-data/{phase}", dependencies=[Depends(require_editor_anywhere)])
async def save_phase_data(
    client_id: str,
    program_id: str,
    phase: str,
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Save structured analyst data (assets, priorities, validation table, etc.) for any phase."""
    if phase not in PHASES:
        raise HTTPException(status_code=400, detail=f"Phase must be one of {PHASES}")
    pn = _get_phase_note(db, client_id, program_id, phase)
    pn.phase_data_json = payload
    db.commit()
    return {"saved": True}


# ── Save analyst-edited AI brief ──────────────────────────────────────────────

@router.put("/{program_id}/ai-brief/{phase}", dependencies=[Depends(require_editor_anywhere)])
async def save_ai_brief(
    client_id: str,
    program_id: str,
    phase: str,
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Overwrite the AI brief with analyst-edited content."""
    if phase not in PHASES:
        raise HTTPException(status_code=400, detail=f"Phase must be one of {PHASES}")
    pn = _get_phase_note(db, client_id, program_id, phase)
    pn.ai_brief = payload.get("brief", "")
    db.commit()
    return {"saved": True}


# ── Scope: asset discovery ─────────────────────────────────────────────────────

@router.get("/{program_id}/scope/assets")
async def get_scope_assets(
    client_id: str,
    program_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> Dict[str, Any]:
    """Return unique resources from findings + existing analyst tags from scope phase_data_json.
    If the scope phase has no saved assets yet, auto-discover and persist them now."""
    pn = _get_phase_note(db, client_id, program_id, "scope")

    # If the phase has never been seeded, discover and persist immediately
    saved_assets: List[Dict] = (pn.phase_data_json or {}).get("assets", [])
    if not saved_assets:
        discovered = _discover_assets(db, client_id)
        if discovered:
            pn.phase_data_json = {"assets": discovered}
            db.commit()
            saved_assets = discovered

    # Merge saved analyst tags with a fresh discovery pass to pick up new findings
    existing_tags: Dict[str, Dict] = {
        f"{a.get('resource_id','')}__{a.get('resource_type','')}": a
        for a in saved_assets
    }
    fresh = _discover_assets(db, client_id)
    seen_keys: set = set()
    assets = []
    for item in fresh:
        key = f"{item['resource_id']}__{item['resource_type']}"
        seen_keys.add(key)
        tag = existing_tags.get(key, {})
        assets.append({
            **item,
            "scope_status": tag.get("scope_status", "untagged"),
            "notes": tag.get("notes", ""),
        })
    # Preserve analyst-tagged assets not in the latest discovery (e.g. retired resources)
    for key, a in existing_tags.items():
        if key not in seen_keys and a.get("scope_status", "untagged") != "untagged":
            assets.append(a)

    connectors = db.query(Connector).filter(Connector.client_id == client_id).all()
    return {
        "assets": assets,
        "connectors": [{"id": c.id, "name": c.name, "type": c.connector_type, "status": c.status} for c in connectors],
    }


# ── Discover: filtered findings by scoped assets ──────────────────────────────

@router.get("/{program_id}/discover/findings")
async def get_discover_findings(
    client_id: str,
    program_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> Dict[str, Any]:
    """Return findings scoped to in-scope / crown-jewel assets from the scope phase."""
    scope_pn = _get_phase_note(db, client_id, program_id, "scope")
    scoped_resources: List[str] = []
    if scope_pn.phase_data_json and "assets" in scope_pn.phase_data_json:
        scoped_resources = [
            a["resource_id"]
            for a in scope_pn.phase_data_json["assets"]
            if a.get("scope_status") in ("in_scope", "crown_jewel") and a.get("resource_id")
        ]

    q = db.query(Finding).join(Scan).filter(Scan.client_id == client_id)
    if scoped_resources:
        q = q.filter(Finding.resource_id.in_(scoped_resources))

    findings = q.all()

    # Group by exposure category
    cat_map: Dict[str, Dict] = {}
    for f in findings:
        cat = _exposure_category(f.resource_type)
        if cat not in cat_map:
            cat_map[cat] = {"category": cat, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        cat_map[cat]["total"] += 1
        sev = (f.severity or "info").lower()
        if sev in cat_map[cat]:
            cat_map[cat][sev] += 1

    # Recent 10 open findings for the table
    recent = (
        q.filter(Finding.status == "open")
        .order_by(Finding.created_at.desc())
        .limit(20)
        .all()
    )

    return {
        "scoped_asset_count": len(scoped_resources),
        "all_assets_mode": len(scoped_resources) == 0,
        "findings_total": len(findings),
        "exposure_categories": list(cat_map.values()),
        "recent_open_findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "exposure_category": _exposure_category(f.resource_type),
                "cvss": f.cvss_score,
                "cve": f.cve_id,
                "status": f.status,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in recent
        ],
    }


# ── Prioritise: AI-generated priority list ────────────────────────────────────

@router.post("/{program_id}/prioritise/generate", dependencies=[Depends(require_editor_anywhere)])
async def generate_priorities(
    client_id: str,
    program_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> Dict[str, Any]:
    """Generate AI top-5 priority items and merge into existing phase_data_json."""
    scope_pn = _get_phase_note(db, client_id, program_id, "scope")
    prio_pn = _get_phase_note(db, client_id, program_id, "prioritise")

    scoped_resources: List[str] = []
    crown_jewels: List[str] = []
    if scope_pn.phase_data_json and "assets" in scope_pn.phase_data_json:
        for a in scope_pn.phase_data_json["assets"]:
            if a.get("scope_status") in ("in_scope", "crown_jewel") and a.get("resource_id"):
                scoped_resources.append(a["resource_id"])
            if a.get("scope_status") == "crown_jewel":
                crown_jewels.append(a["resource_id"])

    q = db.query(Finding).join(Scan).filter(Scan.client_id == client_id, Finding.status == "open")
    if scoped_resources:
        q = q.filter(Finding.resource_id.in_(scoped_resources))
    top = q.order_by(Finding.cvss_score.desc().nullslast()).limit(30).all()

    # Build LLM prompt
    finding_lines = "\n".join(
        f"- [{f.severity.upper()}] {f.title} | Resource: {f.resource_id} | CVSS: {f.cvss_score or 'N/A'} | CVE: {f.cve_id or 'N/A'}"
        for f in top[:20]
    )
    crown_line = f"Crown jewel assets (highest business criticality): {', '.join(crown_jewels)}" if crown_jewels else "No crown jewels tagged."
    prompt = (
        f"You are a senior cybersecurity consultant performing CTEM prioritisation.\n"
        f"{crown_line}\n\n"
        f"Open findings for scoped assets:\n{finding_lines}\n\n"
        "Select the top 5 exposures to remediate first. For each item output EXACTLY this JSON format:\n"
        '[{"rank":1,"title":"...","severity":"critical|high|medium|low","rationale":"...","finding_ids":["id1"]},...]'
        "\nOutput only the JSON array, no other text."
    )

    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        llm = get_llm()
        result = llm.invoke([
            SystemMessage(content="You are a CTEM analyst. Output valid JSON only."),
            HumanMessage(content=prompt),
        ])
        raw = result.content if hasattr(result, "content") else str(result)
        # Extract JSON array
        start, end = raw.find("["), raw.rfind("]")
        ai_items = json.loads(raw[start:end + 1]) if start >= 0 and end > start else []
    except Exception as exc:
        logger.warning("Priority generation failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"AI provider unavailable: {exc}")

    # Merge: keep analyst items (source='analyst'), replace AI items
    existing = prio_pn.phase_data_json or {}
    analyst_items = [i for i in existing.get("items", []) if i.get("source") == "analyst"]
    new_ai_items = [dict(source="ai", analyst_notes="", **i) for i in ai_items]
    all_items = new_ai_items + analyst_items
    # Re-rank
    for idx, item in enumerate(all_items):
        item["rank"] = idx + 1

    prio_pn.phase_data_json = {**existing, "items": all_items}
    db.commit()
    return {"items": all_items}


# ── AI brief generation ────────────────────────────────────────────────────────

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
    pn = _get_phase_note(db, client_id, program_id, phase)
    phase_data = _fetch_phase_data(client_id, phase, pn, db)
    prompt = _build_brief_prompt(phase, phase_data, pn.program.name, pn.program.description)

    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        llm = get_llm()
        result = llm.invoke([
            SystemMessage(content=(
                "You are a senior cybersecurity consultant writing a concise, actionable CTEM phase analysis. "
                "Ground your analysis strictly in the data provided. Use bullet points and clear headings. "
                "Be direct and specific — no generic advice. Limit to 400 words."
            )),
            HumanMessage(content=prompt),
        ])
        brief_text = result.content if hasattr(result, "content") else str(result)
    except Exception as exc:
        logger.warning("AI brief generation failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"AI provider unavailable: {exc}")

    pn.ai_brief = brief_text
    pn.ai_brief_generated_at = datetime.now(timezone.utc)
    db.commit()
    return {"brief": brief_text, "generated_at": pn.ai_brief_generated_at.isoformat()}


def _fetch_phase_data(client_id: str, phase: str, pn: CTEMPhaseNote, db: Session) -> Dict[str, Any]:
    """Gather context for the AI brief prompt."""
    now = datetime.now(timezone.utc)
    pd = pn.phase_data_json or {}

    if phase == "scope":
        connectors = db.query(Connector).filter(Connector.client_id == client_id).all()
        assets = pd.get("assets", [])
        return {
            "connectors_active": sum(1 for c in connectors if c.status == ConnectorStatus.ACTIVE),
            "assets_total": len(assets),
            "in_scope": sum(1 for a in assets if a.get("scope_status") == "in_scope"),
            "crown_jewels": [a["resource_id"] for a in assets if a.get("scope_status") == "crown_jewel"],
            "out_of_scope": sum(1 for a in assets if a.get("scope_status") == "out_of_scope"),
        }

    elif phase == "discover":
        scoped = [a["resource_id"] for a in (pd.get("assets") or []) if a.get("scope_status") in ("in_scope", "crown_jewel")]
        q = db.query(Finding).join(Scan).filter(Scan.client_id == client_id)
        if scoped:
            q = q.filter(Finding.resource_id.in_(scoped))
        total = q.count()
        sev: Dict[str, int] = {}
        for s in ["critical", "high", "medium", "low"]:
            sev[s] = q.filter(Finding.severity == s).count()
        cats = pd.get("categories", [])
        return {"findings_total": total, "by_severity": sev, "exposure_categories": len(cats)}

    elif phase == "prioritise":
        items = pd.get("items", [])
        return {"priority_items": items[:5], "analyst_additions": sum(1 for i in items if i.get("source") == "analyst")}

    elif phase == "validate":
        methods = pd.get("methods", [])
        total_tests = sum(m.get("tests_run", 0) or 0 for m in methods)
        total_confirmed = sum(m.get("confirmed", 0) or 0 for m in methods if m.get("confirmed"))
        return {"validation_methods": methods, "total_tests": total_tests, "total_confirmed": total_confirmed, "notable_findings": pd.get("notable_findings", "")}

    elif phase == "mobilise":
        owners = pd.get("owners", [])
        total_breach = sum(o.get("sla_breach", 0) or 0 for o in owners)
        sla_data: Dict[str, int] = {}
        for sev, hours in _SLA.items():
            sla_data[sev] = (
                db.query(func.count(Finding.id))
                .join(Scan)
                .filter(Scan.client_id == client_id, Finding.severity == sev, Finding.status == "open", Finding.created_at < now - timedelta(hours=hours))
                .scalar() or 0
            )
        return {"owner_teams": owners, "sla_breaches": sla_data, "tracked_sla_breaches": total_breach, "blockers": pd.get("blockers", [])}

    return {}


def _build_brief_prompt(phase: str, data: Dict[str, Any], program_name: str, program_desc: Optional[str]) -> str:
    desc_line = f"Program description: {program_desc}" if program_desc else ""
    data_str = json.dumps(data, indent=2, default=str)

    INSTRUCTIONS = {
        "scope": (
            "Write a Scope phase brief covering:\n"
            "1. Assessment of the scope coverage (are the right assets in scope?)\n"
            "2. Whether any crown jewels have been identified and why they matter\n"
            "3. Recommended scope statement for this CTEM cycle\n"
        ),
        "discover": (
            "Write a Discovery phase brief covering:\n"
            "1. Summary of the attack surface footprint across exposure categories\n"
            "2. Which exposure categories have the most risk concentration\n"
            "3. Coverage gaps and recommended additional scanning\n"
            "4. Notable patterns (e.g. identity exposure trends, third-party findings)\n"
        ),
        "prioritise": (
            "Write a Prioritisation phase brief covering:\n"
            "1. Rationale for the top priority items\n"
            "2. Any items that need immediate escalation (critical + crown jewel combinations)\n"
            "3. Recommended sequencing for remediation teams\n"
        ),
        "validate": (
            "Write a Validation phase brief covering:\n"
            "1. Summary of validation coverage (what % of findings have been validated)\n"
            "2. Key confirmed-exploitable findings and their business impact\n"
            "3. Gaps — what has not yet been validated and why that matters\n"
            "4. Control effectiveness assessment based on BAS/red team results\n"
        ),
        "mobilise": (
            "Write a Mobilisation phase brief covering:\n"
            "1. Overall SLA compliance status and which teams are on/off track\n"
            "2. Key blockers preventing timely remediation and recommended escalations\n"
            "3. Compensating controls that should be applied where SLA will be missed\n"
            "4. Recommended actions for the next 2 weeks\n"
        ),
    }

    return (
        f"CTEM Program: {program_name}\n"
        f"{desc_line}\n"
        f"Phase: {phase.upper()}\n\n"
        f"Platform data:\n{data_str}\n\n"
        f"{INSTRUCTIONS.get(phase, 'Provide an analysis.')}\n"
        "Be specific to the data above. Do not invent numbers."
    )


# ── Report export (PDF / DOCX) ────────────────────────────────────────────────

@router.get("/{program_id}/export")
async def export_ctem_report(
    client_id: str,
    program_id: str,
    format: str = "pdf",
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Export the full CTEM program as a rich PDF or DOCX report."""
    program = db.query(CTEMProgram).filter(CTEMProgram.id == program_id, CTEMProgram.client_id == client_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="CTEM program not found")
    _ensure_phases(db, program)

    # Build phase map
    phase_map: Dict[str, CTEMPhaseNote] = {pn.phase: pn for pn in program.phases}

    try:
        from services.ctem_export import generate_ctem_pdf, generate_ctem_docx
        if format == "docx":
            buf = generate_ctem_docx(program, phase_map)
            media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            filename = f"CTEM-{program.name[:40]}.docx"
        else:
            buf = generate_ctem_pdf(program, phase_map)
            media_type = "application/pdf"
            filename = f"CTEM-{program.name[:40]}.pdf"
    except Exception as exc:
        logger.error("CTEM export failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Export failed: {exc}")

    return StreamingResponse(
        buf,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
