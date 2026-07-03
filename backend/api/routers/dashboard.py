"""Dashboard summary endpoint."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from api.models.models import (
    Client, Connector, Finding, Risk, Scan, ScanStatus, FrameworkAssessment,
    AgentRun, ThreatModel, ScheduledMissionRun, ScheduledMission,
)
from api.schemas.schemas import DashboardSummary
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _posture_health(open_findings: int, critical_findings: int, total_connectors: int,
                    active_connectors: int, scans_last_30d: int, avg_compliance: float) -> Dict[str, float]:
    """Calculate approximate posture health scores from DB metrics."""
    # Vulnerability Management: penalise by critical/high finding density
    vm = max(0.0, 100.0 - critical_findings * 8 - max(open_findings - critical_findings, 0) * 2)
    vm = min(vm, 100.0)

    # Identity & Access: connector health ratio
    ia = round((active_connectors / max(total_connectors, 1)) * 100, 1) if total_connectors else 50.0

    # Data Protection: compliance score average (or default 50 if no data)
    dp = round(avg_compliance, 1) if avg_compliance else 50.0

    # Threat Detection: whether scans are happening regularly
    td = min(100.0, 20.0 + scans_last_30d * 10)

    return {
        "Vulnerability Management": round(vm, 1),
        "Identity & Access": round(ia, 1),
        "Data Protection": round(dp, 1),
        "Threat Detection": round(td, 1),
    }


@router.get("/", response_model=DashboardSummary)
async def get_dashboard(db: Session = Depends(get_db), _=Depends(get_current_user)):
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    # Subquery of non-deleted client IDs — used everywhere to exclude soft-deleted clients
    active_cids = db.query(Client.id).filter(Client.deleted_at.is_(None))

    total_clients = db.query(func.count(Client.id)).filter(
        Client.is_active == True, Client.deleted_at.is_(None)
    ).scalar() or 0
    total_connectors = db.query(func.count(Connector.id)).scalar() or 0
    active_connectors = db.query(func.count(Connector.id)).filter(Connector.status == "active").scalar() or 0

    # Findings filtered through Scan.client_id to exclude soft-deleted clients
    open_findings = (
        db.query(func.count(Finding.id))
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(Finding.status == "open", Scan.client_id.in_(active_cids))
        .scalar() or 0
    )
    critical_findings = (
        db.query(func.count(Finding.id))
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(Finding.status == "open", Finding.severity == "critical", Scan.client_id.in_(active_cids))
        .scalar() or 0
    )
    findings_by_severity = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    for sev, n in (
        db.query(Finding.severity, func.count(Finding.id))
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(Finding.status == "open", Scan.client_id.in_(active_cids))
        .group_by(Finding.severity).all()
    ):
        key = sev.value if hasattr(sev, "value") else str(sev)
        findings_by_severity[key] = findings_by_severity.get(key, 0) + int(n or 0)

    risks_open = (
        db.query(func.count(Risk.id))
        .filter(Risk.status == "open", Risk.client_id.in_(active_cids))
        .scalar() or 0
    )
    scans_last_30d = (
        db.query(func.count(Scan.id))
        .filter(Scan.created_at >= thirty_days_ago, Scan.client_id.in_(active_cids))
        .scalar() or 0
    )
    agent_runs_total = db.query(func.count(AgentRun.id)).scalar() or 0

    # Compliance scores per framework — active clients only
    assessments = (
        db.query(FrameworkAssessment)
        .filter(FrameworkAssessment.client_id.in_(active_cids))
        .order_by(FrameworkAssessment.assessed_at.desc())
        .limit(20).all()
    )
    scores: Dict[str, float] = {}
    for a in assessments:
        key = a.framework.value if hasattr(a.framework, "value") else str(a.framework)
        if key not in scores:
            scores[key] = a.overall_score or 0.0
    avg_compliance = sum(scores.values()) / len(scores) if scores else 0.0

    # Recent data for activity feeds — active clients only
    recent_scans_raw = (
        db.query(Scan)
        .filter(Scan.client_id.in_(active_cids))
        .order_by(Scan.created_at.desc()).limit(5).all()
    )
    recent_scans = [
        {"id": s.id, "client_id": s.client_id, "scan_type": s.scan_type.value if hasattr(s.scan_type, "value") else s.scan_type,
         "status": s.status.value if hasattr(s.status, "value") else s.status,
         "framework": s.framework.value if hasattr(s.framework, "value") else s.framework,
         "created_at": s.created_at.isoformat() if s.created_at else None,
         "summary": s.summary}
        for s in recent_scans_raw
    ]

    recent_risks_raw = (
        db.query(Risk)
        .filter(Risk.status == "open", Risk.client_id.in_(active_cids))
        .order_by(Risk.created_at.desc()).limit(5).all()
    )
    recent_risks = [
        {"id": r.id, "client_id": r.client_id, "title": r.title,
         "risk_level": r.risk_level.value if hasattr(r.risk_level, "value") else r.risk_level,
         "risk_score": r.risk_score, "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in recent_risks_raw
    ]

    recent_findings_raw = (
        db.query(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(Finding.status == "open", Finding.severity.in_(["critical", "high"]), Scan.client_id.in_(active_cids))
        .order_by(Finding.created_at.desc()).limit(5).all()
    )
    recent_findings = [
        {"id": f.id, "scan_id": f.scan_id, "title": f.title,
         "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
         "resource_id": f.resource_id, "cve_id": f.cve_id,
         "created_at": f.created_at.isoformat() if f.created_at else None}
        for f in recent_findings_raw
    ]

    posture = _posture_health(open_findings, critical_findings, total_connectors, active_connectors, scans_last_30d, avg_compliance)

    return DashboardSummary(
        total_clients=total_clients,
        active_connectors=active_connectors,
        open_findings=open_findings,
        critical_findings=critical_findings,
        findings_by_severity=findings_by_severity,
        risks_open=risks_open,
        scans_last_30d=scans_last_30d,
        compliance_scores=scores,
        posture_health=posture,
        recent_scans=recent_scans,
        recent_risks=recent_risks,
        recent_findings=recent_findings,
        agent_runs_total=agent_runs_total,
    )


@router.get("/activity")
async def get_activity_feed(
    days: int = 3,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Unified activity feed across all engagement types, last N days.

    Aggregates scans, threat models, mission runs, risks (open critical /
    high only), and agent runs into one timeline sorted by timestamp.
    Total events capped at 80 so the response stays small."""
    days = max(1, min(days, 30))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    events: List[Dict[str, Any]] = []

    # Build a quick id→name lookup so we don't issue one query per event
    client_names: Dict[str, str] = {
        c.id: c.name for c in db.query(Client.id, Client.name).all()  # type: ignore[arg-type]
    }

    def client_name(cid: Optional[str]) -> str:
        return client_names.get(cid or "", "—")

    # ── Scans ────────────────────────────────────────────────────────────────
    scans = (
        db.query(Scan)
        .filter(Scan.created_at >= cutoff)
        .order_by(Scan.created_at.desc())
        .limit(60)
        .all()
    )
    for s in scans:
        status = s.status.value if hasattr(s.status, "value") else str(s.status or "")
        scan_type = s.scan_type.value if hasattr(s.scan_type, "value") else str(s.scan_type or "")
        events.append({
            "kind": "scan",
            "label": f"{scan_type.replace('_', ' ').title()} scan {status}",
            "target": (s.summary or {}).get("target") if isinstance(s.summary, dict) else None,
            "client_id": s.client_id,
            "client_name": client_name(s.client_id),
            "status": status,
            "when_iso": (s.created_at or datetime.now(timezone.utc)).isoformat(),
            "link": f"/scans/{s.id}",
        })

    # ── Threat models ────────────────────────────────────────────────────────
    tms = (
        db.query(ThreatModel)
        .filter(ThreatModel.created_at >= cutoff)
        .order_by(ThreatModel.created_at.desc())
        .limit(40)
        .all()
    )
    for t in tms:
        events.append({
            "kind": "threat_model",
            "label": f"Threat model · {(t.methodology or 'stride').upper()} · {t.status or 'pending'}",
            "target": t.name,
            "client_id": t.client_id,
            "client_name": client_name(t.client_id),
            "status": t.status or "pending",
            "when_iso": ((t.generated_at or t.created_at) or datetime.now(timezone.utc)).isoformat(),
            "link": f"/threat-models/{t.id}?client={t.client_id}",
        })

    # ── Workflow / mission runs ──────────────────────────────────────────────
    mruns = (
        db.query(ScheduledMissionRun, ScheduledMission)
        .join(ScheduledMission, ScheduledMission.id == ScheduledMissionRun.mission_id)
        .filter(ScheduledMissionRun.completed_at >= cutoff)
        .order_by(ScheduledMissionRun.completed_at.desc())
        .limit(40)
        .all()
    )
    for run, mission in mruns:
        mtype = mission.mission_type.value if hasattr(mission.mission_type, "value") else str(mission.mission_type or "")
        status = run.status.value if hasattr(run.status, "value") else str(run.status or "")
        events.append({
            "kind": "workflow",
            "label": f"{mtype.replace('_', ' ').title()} · {status}",
            "target": mission.name,
            "client_id": mission.client_id,
            "client_name": client_name(mission.client_id),
            "status": status,
            "when_iso": (run.completed_at or run.created_at or datetime.now(timezone.utc)).isoformat(),
            "link": f"/missions",
        })

    # ── New high-impact risks ────────────────────────────────────────────────
    risks = (
        db.query(Risk)
        .filter(Risk.created_at >= cutoff)
        .filter(Risk.risk_level.in_(["critical", "high"]))
        .order_by(Risk.created_at.desc())
        .limit(40)
        .all()
    )
    for r in risks:
        lvl = r.risk_level.value if hasattr(r.risk_level, "value") else str(r.risk_level or "")
        events.append({
            "kind": "risk",
            "label": f"New {lvl.upper()} risk",
            "target": r.title,
            "client_id": r.client_id,
            "client_name": client_name(r.client_id),
            "status": (r.status or "open"),
            "when_iso": (r.created_at or datetime.now(timezone.utc)).isoformat(),
            "link": f"/risks",
        })

    # ── Agent runs ───────────────────────────────────────────────────────────
    aruns = (
        db.query(AgentRun)
        .filter(AgentRun.started_at >= cutoff)
        .order_by(AgentRun.started_at.desc())
        .limit(40)
        .all()
    )
    for a in aruns:
        agent_label: Optional[str] = None
        if isinstance(a.input_data, dict):
            agent_label = a.input_data.get("agent_name") or a.input_data.get("agent_key")
        if not agent_label:
            agent_label = (a.agent_type.value if hasattr(a.agent_type, "value") else str(a.agent_type or "agent")).replace("_", " ").title()
        events.append({
            "kind": "agent",
            "label": f"{agent_label}",
            "target": None,
            "client_id": a.client_id,
            "client_name": client_name(a.client_id),
            "status": (a.status or "completed"),
            "when_iso": (a.completed_at or a.started_at or datetime.now(timezone.utc)).isoformat(),
            "link": f"/scans/{a.scan_id}" if a.scan_id else "/agents",
        })

    events.sort(key=lambda e: e["when_iso"], reverse=True)
    return {"days": days, "events": events[:80]}
