"""Cross-client scan listing and per-scan detail for the Assessments page.

The legacy `/clients/{cid}/scans/` lives in scans.py — that endpoint stays
unchanged. This module exposes the tile-view + detail-view shape:

  GET  /scans/all              → flat list across all clients (admin-scoped),
                                  enriched with category, client_name,
                                  duration, agent-run summary
  GET  /scans/{scan_id}/detail → deep payload: scan + findings (RPS-enriched)
                                  + past AgentRun rows + ai_verdict
  POST /scans/{scan_id}/generate-verdict → kick off the verdict generator
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from api.models.models import (
    AgentRun, Client, Connector, ConnectorType, Finding, Scan, ScanStatus,
)
from db.database import get_db
from core.security import get_current_user
from core.authz import get_user_grants, is_admin_anywhere
from api.models.models import UserAccess, AccessRole, AccessScope
from services.verdict import (
    _category_for_connector, _tool_label_for_connector,
    compute_rps, generate_verdict, generate_verdict_bg,
)

router = APIRouter(tags=["scans-overview"])


def _user_email(user: dict) -> str:
    for k in ("preferred_username", "upn", "email"):
        v = user.get(k)
        if v:
            return v.lower()
    return ""


def _accessible_ids(db: Session, user: dict) -> Optional[set]:
    """Return the set of client IDs the user can see, or None if the user
    is a global admin (None means: no filter, see everything)."""
    from core.config import get_settings as _gs
    email = _user_email(user)
    # INITIAL_ADMIN_EMAILS users bypass all grant checks (mirrors get_current_user logic)
    initial_admins = {
        e.strip().lower()
        for e in (_gs().INITIAL_ADMIN_EMAILS or "").split(",")
        if e.strip()
    }
    if email and email in initial_admins:
        return None
    if not email:
        return set()
    try:
        grants = get_user_grants(db, email)
    except Exception:
        return None  # Fail open on DB error — don't silently hide all scans
    # No grants at all: user passed get_current_user (authenticated) but grants
    # haven't been bootstrapped yet (race condition or migration gap). Fail open.
    if not grants:
        return None
    # Global admin grant → full access
    for g in grants:
        scope = g.scope_type.value if hasattr(g.scope_type, "value") else str(g.scope_type)
        if scope == "global":
            return None
    # Otherwise: union of client scopes + parent clients of project grants
    visible: set = set()
    project_parent_lookup: List[str] = []
    for g in grants:
        scope = g.scope_type.value if hasattr(g.scope_type, "value") else str(g.scope_type)
        if scope == "client" and g.scope_id:
            visible.add(g.scope_id)
        elif scope == "project" and g.scope_id:
            project_parent_lookup.append(g.scope_id)
    if project_parent_lookup:
        from api.models.models import Project
        for cid, in db.query(Project.client_id).filter(Project.id.in_(project_parent_lookup)).all():
            if cid:
                visible.add(cid)
    return visible


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Coerce a possibly-naive datetime to UTC-aware. SQLite (dev) returns
    naive datetimes; mssql (prod) returns aware. Without this coercion,
    subtracting from `datetime.now(timezone.utc)` raises TypeError and
    crashes the /scans/all endpoint."""
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _duration_seconds(s: Scan) -> Optional[int]:
    started = _aware(s.started_at)
    completed = _aware(s.completed_at)
    if started and completed:
        return int((completed - started).total_seconds())
    if started and s.status in (ScanStatus.RUNNING, ScanStatus.PENDING):
        return int((datetime.now(timezone.utc) - started).total_seconds())
    return None


def _connector_type_value(conn: Optional[Connector]) -> str:
    if not conn:
        return ""
    ct = conn.connector_type
    return ct.value if hasattr(ct, "value") else str(ct)


@router.get("/scans/all")
async def list_all_scans(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Cross-client tile feed. Filters to clients the user has access to.

    Returns each scan with:
      - category (DAST/SAST/Network/Dependency/Cloud/Other)
      - client_name
      - duration_seconds
      - tile_name = f"{category} · {client_name}"
      - agents_ran (count + types)
      - findings_count
      - has_verdict
    """
    q = db.query(Scan).order_by(Scan.created_at.desc()).limit(500)
    scans = q.all()
    allowed = _accessible_ids(db, user)
    if allowed is not None:
        scans = [s for s in scans if s.client_id in allowed]

    # Bulk-resolve client names + connector types
    client_ids = {s.client_id for s in scans if s.client_id}
    conn_ids = {s.connector_id for s in scans if s.connector_id}
    client_names: Dict[str, str] = {}
    if client_ids:
        for cid, name in db.query(Client.id, Client.name).filter(Client.id.in_(client_ids)).all():
            client_names[cid] = name
    conn_types: Dict[str, str] = {}
    if conn_ids:
        for cid, ct in db.query(Connector.id, Connector.connector_type).filter(Connector.id.in_(conn_ids)).all():
            conn_types[cid] = ct.value if hasattr(ct, "value") else str(ct)

    # Bulk-load finding counts + agent-run counts
    scan_ids = [s.id for s in scans]
    finding_counts: Dict[str, int] = defaultdict(int)
    if scan_ids:
        from sqlalchemy import func as _f
        for sid, n in (
            db.query(Finding.scan_id, _f.count(Finding.id))
            .filter(Finding.scan_id.in_(scan_ids))
            .group_by(Finding.scan_id).all()
        ):
            finding_counts[sid] = int(n)
    agent_runs_by_scan: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    if scan_ids:
        for ar in db.query(AgentRun).filter(AgentRun.scan_id.in_(scan_ids)).all():
            agent_type = ar.agent_type.value if hasattr(ar.agent_type, "value") else str(ar.agent_type)
            # Catalog buddies all persist as agent_type="orchestrator"; their
            # real identity lives in input_data. Surface key + friendly name so
            # the Assessment tile can list distinct buddies instead of
            # collapsing every advisory run into a single "orchestrator".
            idata = ar.input_data or {}
            agent_runs_by_scan[ar.scan_id].append({
                "id": ar.id, "agent_type": agent_type, "status": ar.status,
                "agent_key": idata.get("agent_key") or agent_type,
                "agent_name": idata.get("agent_name") or agent_type.replace("_", " ").title(),
            })

    out: List[Dict[str, Any]] = []
    for s in scans:
        client_name = client_names.get(s.client_id, "Unknown Client")
        connector_type = conn_types.get(s.connector_id or "", "")
        # Infer scanner type from summary when no connector is linked
        # (e.g. AI Code Review via archive upload, inline repo_url)
        if not connector_type:
            _sum = s.summary or {}
            connector_type = (
                _sum.get("scanner")
                or ("ai_code_review" if (_sum.get("repo_url") or _sum.get("code_archive")) else "")
            )
        category = _category_for_connector(connector_type) if connector_type else _category_for_connector("")
        status = s.status.value if hasattr(s.status, "value") else str(s.status)
        out.append({
            "id": s.id,
            "client_id": s.client_id,
            "client_name": client_name,
            "connector_type": connector_type,
            "category": category,
            "tile_name": _tool_label_for_connector(connector_type),
            "name": s.name,
            "scan_type": s.scan_type.value if hasattr(s.scan_type, "value") else str(s.scan_type),
            "framework": (s.framework.value if hasattr(s.framework, "value") else (s.framework or None)) if s.framework else None,
            "status": status,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "duration_seconds": _duration_seconds(s),
            "findings_count": finding_counts.get(s.id, 0),
            "summary": s.summary or {},
            "agents_ran": agent_runs_by_scan.get(s.id, []),
            "has_verdict": bool(s.ai_verdict),
            "error_message": s.error_message,
            "parent_scan_id": s.parent_scan_id,
        })
    return {"scans": out}


@router.get("/scans/{scan_id}/detail")
async def scan_detail(
    scan_id: str,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    allowed = _accessible_ids(db, user)
    if allowed is not None and s.client_id not in allowed:
        raise HTTPException(status_code=403, detail="No access to this scan's client")

    client = db.query(Client).filter(Client.id == s.client_id).first()
    conn = db.query(Connector).filter(Connector.id == s.connector_id).first() if s.connector_id else None
    connector_type = _connector_type_value(conn)
    if not connector_type:
        _sum = s.summary or {}
        connector_type = (
            _sum.get("scanner")
            or ("ai_code_review" if (_sum.get("repo_url") or _sum.get("code_archive")) else "")
        )
    category = _category_for_connector(connector_type)

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    findings_out = []
    for f in findings:
        rps = compute_rps(f)
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        findings_out.append({
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "severity": sev,
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "control_id": f.control_id,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "remediation": f.remediation,
            "evidence": f.evidence or {},
            "rps": rps,
        })

    agent_runs = (
        db.query(AgentRun)
        .filter(AgentRun.scan_id == scan_id)
        .order_by(AgentRun.started_at.desc())
        .all()
    )
    agent_runs_out = []
    for ar in agent_runs:
        agent_type = ar.agent_type.value if hasattr(ar.agent_type, "value") else str(ar.agent_type)
        agent_runs_out.append({
            "id": ar.id,
            "agent_type": agent_type,
            "status": ar.status,
            "started_at": ar.started_at.isoformat() if ar.started_at else None,
            "completed_at": ar.completed_at.isoformat() if ar.completed_at else None,
            "output_data": ar.output_data,
            "input_data": ar.input_data,
            "error_message": ar.error_message,
            "tokens_used": ar.tokens_used,
        })

    return {
        "id": s.id,
        "client_id": s.client_id,
        "client_name": client.name if client else "Unknown Client",
        "category": category,
        "tile_name": _tool_label_for_connector(connector_type),
        "name": s.name,
        "scan_type": s.scan_type.value if hasattr(s.scan_type, "value") else str(s.scan_type),
        "framework": (s.framework.value if hasattr(s.framework, "value") else s.framework) if s.framework else None,
        "status": s.status.value if hasattr(s.status, "value") else str(s.status),
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "duration_seconds": _duration_seconds(s),
        "summary": s.summary or {},
        "error_message": s.error_message,
        "findings": findings_out,
        "agent_runs": agent_runs_out,
        "ai_verdict": s.ai_verdict,
        "ai_verdict_generated_at": s.ai_verdict_generated_at.isoformat() if s.ai_verdict_generated_at else None,
    }


@router.post("/scans/{scan_id}/generate-verdict")
async def trigger_verdict(
    scan_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Manually (re)generate the structured verdict. Returns immediately;
    the verdict is filled in by a background task and visible on the next
    GET /scans/{scan_id}/detail."""
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    allowed = _accessible_ids(db, user)
    if allowed is not None and s.client_id not in allowed:
        raise HTTPException(status_code=403, detail="No access to this scan's client")
    if s.status.value not in ("completed", "failed") and not hasattr(s.status, "value"):
        # Allow on completed; for running scans, still queue (verdict will reflect partial data)
        pass
    background_tasks.add_task(generate_verdict_bg, scan_id)
    return {"queued": True, "scan_id": scan_id}
