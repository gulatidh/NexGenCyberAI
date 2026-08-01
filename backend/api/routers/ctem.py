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


def _discover_assets(db: Session, client_id: str, connector_ids: List[str] = None) -> List[Dict]:
    """Return unique assets for scope pre-seeding.

    When connector_ids is provided, query the Asset table filtered to those connectors
    and deduplicate by external_id (same resource discovered by multiple connectors → one row).
    Otherwise fall back to finding resource_ids (legacy behaviour for programs with no connector scope).
    """
    from api.models.models import Asset

    if connector_ids:
        # Asset-centric path: deduplicate by external_id across selected connectors
        asset_rows = (
            db.query(Asset)
            .filter(
                Asset.client_id == client_id,
                Asset.connector_id.in_(connector_ids),
            )
            .order_by(Asset.name)
            .limit(500)
            .all()
        )
        # Deduplicate by external_id — same asset from multiple connectors → keep first seen
        seen_external: Dict[str, bool] = {}
        unique_assets: List[Asset] = []
        for a in asset_rows:
            if a.external_id not in seen_external:
                seen_external[a.external_id] = True
                unique_assets.append(a)

        # Count open findings per external_id.
        # Build a lookup that covers both external_id and name (handles IP vs DNS mismatch
        # for host-based scanners like Qualys where old assets may have IP as external_id
        # but findings carry the DNS name as resource_id, or vice versa).
        external_ids = list(seen_external.keys())
        # Also collect asset names so we can match findings stored under the DNS name
        external_id_to_name: Dict[str, str] = {a.external_id: (a.name or a.external_id) for a in unique_assets}
        all_lookup_ids = list({v for pair in external_id_to_name.items() for v in pair})
        raw_counts: Dict[str, int] = {}
        if all_lookup_ids:
            rows = (
                db.query(Finding.resource_id, func.count(Finding.id).label("cnt"))
                .join(Scan)
                .filter(
                    Scan.client_id == client_id,
                    Scan.is_live == True,
                    Finding.duplicate_of_id.is_(None),
                    Finding.status == "open",
                    Finding.resource_id.in_(all_lookup_ids),
                )
                .group_by(Finding.resource_id)
                .all()
            )
            raw_counts = {r.resource_id: r.cnt for r in rows}

        assets = []
        for a in unique_assets:
            # Try external_id first; fall back to name for IP↔DNS mismatches (Qualys etc.)
            cnt = raw_counts.get(a.external_id, 0)
            canonical_rid = a.external_id
            if cnt == 0 and a.name and a.name != a.external_id:
                name_cnt = raw_counts.get(a.name, 0)
                if name_cnt > 0:
                    cnt = name_cnt
                    canonical_rid = a.name  # findings are stored under the DNS name
            assets.append({
                "resource_id": canonical_rid,
                "resource_type": a.asset_class or a.asset_type or "unknown",
                "display_name": a.name or a.external_id,
                "exposure_category": _exposure_category(a.asset_class or a.asset_type),
                "finding_count": cnt,
                "scope_status": "untagged",
                "notes": "",
            })
        return assets

    # Legacy path: derive unique resources from findings (live scans, canonical findings only)
    rows = (
        db.query(Finding.resource_id, Finding.resource_type, func.count(Finding.id).label("cnt"))
        .join(Scan)
        .filter(
            Scan.client_id == client_id,
            Scan.is_live == True,
            Finding.duplicate_of_id.is_(None),
            Finding.status == "open",
            Finding.resource_id.isnot(None),
            Finding.resource_id != "",
        )
        .group_by(Finding.resource_id, Finding.resource_type)
        .order_by(func.count(Finding.id).desc())
        .limit(200)
        .all()
    )
    if not rows:
        rows = (
            db.query(Finding.resource_type, Finding.resource_type, func.count(Finding.id).label("cnt"))
            .join(Scan)
            .filter(
                Scan.client_id == client_id,
                Scan.is_live == True,
                Finding.duplicate_of_id.is_(None),
                Finding.status == "open",
                Finding.resource_type.isnot(None),
                Finding.resource_type != "",
            )
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
    # Auto-seed scope assets so the analyst sees something immediately
    if needs_asset_seed:
        scope_pn = next((p for p in program.phases if p.phase == "scope"), None)
        if scope_pn:
            assets = _discover_assets(db, program.client_id, program.connector_ids or None)
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
        connector_ids_json=json.dumps(payload.connector_ids) if payload.connector_ids else None,
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

    program = (
        db.query(CTEMProgram)
        .filter(CTEMProgram.id == program_id, CTEMProgram.client_id == client_id)
        .first()
    )
    scoped_connector_ids: List[str] = program.connector_ids if program else []

    # If the phase has never been seeded, discover and persist immediately
    saved_assets: List[Dict] = (pn.phase_data_json or {}).get("assets", [])
    if not saved_assets:
        discovered = _discover_assets(db, client_id, scoped_connector_ids or None)
        if discovered:
            pn.phase_data_json = {"assets": discovered}
            db.commit()
            saved_assets = discovered

    # Merge saved analyst tags with a fresh discovery pass to pick up new findings
    existing_tags: Dict[str, Dict] = {
        f"{a.get('resource_id','')}__{a.get('resource_type','')}": a
        for a in saved_assets
    }
    fresh = _discover_assets(db, client_id, scoped_connector_ids or None)
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
        "scoped_connector_ids": scoped_connector_ids,
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

    q = (
        db.query(Finding).join(Scan)
        .filter(
            Scan.client_id == client_id,
            Scan.is_live == True,
            Finding.duplicate_of_id.is_(None),
            Finding.status == "open",
        )
    )
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

    # Recent 20 open findings for the table (already filtered to open above)
    recent = (
        q.order_by(Finding.created_at.desc())
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

    crown_jewel_set = set(crown_jewels)

    q = (
        db.query(Finding).join(Scan)
        .filter(
            Scan.client_id == client_id,
            Scan.is_live == True,
            Finding.duplicate_of_id.is_(None),
            Finding.status == "open",
        )
    )
    if scoped_resources:
        q = q.filter(Finding.resource_id.in_(scoped_resources))
    top = q.order_by(Finding.cvss_score.desc().nullslast()).limit(50).all()

    # Group findings by CVE (or title if no CVE) to detect how many crown jewel assets each exposure hits
    # key: cve_id or title → {findings, crown_jewel_assets affected}
    exposure_map: Dict[str, Dict] = {}
    for f in top:
        key = f.cve_id or f.title or f.id
        if key not in exposure_map:
            exposure_map[key] = {"findings": [], "crown_jewel_assets": set()}
        exposure_map[key]["findings"].append(f)
        if f.resource_id and f.resource_id in crown_jewel_set:
            exposure_map[key]["crown_jewel_assets"].add(f.resource_id)

    # Sort exposures: crown jewel exposures first, then by CVSS
    def _exposure_sort(item):
        findings = item["findings"]
        cj_count = len(item["crown_jewel_assets"])
        max_cvss = max((f.cvss_score or 0) for f in findings)
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_sev = max(sev_order.get(str(f.severity.value if hasattr(f.severity, "value") else f.severity or "").lower(), 0) for f in findings)
        return (-cj_count, -max_sev, -max_cvss)

    sorted_exposures = sorted(exposure_map.values(), key=_exposure_sort)
    top_30 = sorted_exposures[:30]

    # Build AI prompt with crown jewel annotations
    finding_lines_parts = []
    for exp in top_30[:20]:
        f = exp["findings"][0]
        cj_note = f" 👑 CROWN JEWEL ASSET ({len(exp['crown_jewel_assets'])} affected)" if exp["crown_jewel_assets"] else ""
        sev = str(f.severity.value if hasattr(f.severity, "value") else f.severity or "").upper()
        finding_lines_parts.append(
            f"- [{sev}] {f.title} | CVE: {f.cve_id or 'N/A'} | CVSS: {f.cvss_score or 'N/A'} | Resource: {f.resource_id}{cj_note}"
        )
    finding_lines = "\n".join(finding_lines_parts)

    crown_line = (
        f"Crown jewel assets (highest business criticality, must be protected first): {', '.join(crown_jewels)}"
        if crown_jewels else "No crown jewels tagged in scope."
    )
    prompt = (
        f"You are a senior cybersecurity consultant performing CTEM prioritisation.\n"
        f"{crown_line}\n\n"
        f"Open findings (👑 = affects a crown jewel asset):\n{finding_lines}\n\n"
        "Select the top 5 exposures to remediate first. Crown jewel exposures must be ranked higher unless "
        "the severity difference is dramatic. For each item output EXACTLY this JSON format:\n"
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
        start, end = raw.find("["), raw.rfind("]")
        ai_items = json.loads(raw[start:end + 1]) if start >= 0 and end > start else []
    except Exception as exc:
        logger.warning("Priority generation failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"AI provider unavailable: {exc}")

    # Annotate AI items with crown jewel data by matching finding_ids or title
    finding_by_id: Dict[str, Finding] = {f.id: f for exp in sorted_exposures for f in exp["findings"]}
    for item in ai_items:
        fids = item.get("finding_ids") or []
        cj_assets: set = set()
        for fid in fids:
            f = finding_by_id.get(fid)
            if f and f.resource_id in crown_jewel_set:
                cj_assets.add(f.resource_id)
        # Also check title match against exposures
        if not cj_assets:
            for exp in sorted_exposures:
                any_f = exp["findings"][0]
                if (any_f.title or "").lower() in (item.get("title") or "").lower() or \
                   (item.get("title") or "").lower() in (any_f.title or "").lower():
                    cj_assets = exp["crown_jewel_assets"]
                    break
        item["crown_jewel_count"] = len(cj_assets)
        item["affects_crown_jewels"] = len(cj_assets) > 0
        item["crown_jewel_assets"] = list(cj_assets)

    # Merge: keep analyst items (source='analyst'), replace AI items
    existing = prio_pn.phase_data_json or {}
    analyst_items = [i for i in existing.get("items", []) if i.get("source") == "analyst"]
    new_ai_items = [dict(source="ai", analyst_notes="", **i) for i in ai_items]
    all_items = new_ai_items + analyst_items
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
        q = (
            db.query(Finding).join(Scan)
            .filter(
                Scan.client_id == client_id,
                Scan.is_live == True,
                Finding.duplicate_of_id.is_(None),
                Finding.status == "open",
            )
        )
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
                .filter(
                    Scan.client_id == client_id,
                    Scan.is_live == True,
                    Finding.duplicate_of_id.is_(None),
                    Finding.severity == sev,
                    Finding.status == "open",
                    Finding.created_at < now - timedelta(hours=hours),
                )
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
