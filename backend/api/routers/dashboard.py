"""Dashboard summary endpoint."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from typing import Dict
from api.models.models import Client, Connector, Finding, Risk, Scan, ScanStatus, FrameworkAssessment, AgentRun
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
    total_clients = db.query(func.count(Client.id)).filter(Client.is_active == True).scalar() or 0
    total_connectors = db.query(func.count(Connector.id)).scalar() or 0
    active_connectors = db.query(func.count(Connector.id)).filter(Connector.status == "active").scalar() or 0
    open_findings = db.query(func.count(Finding.id)).filter(Finding.status == "open").scalar() or 0
    critical_findings = db.query(func.count(Finding.id)).filter(Finding.status == "open", Finding.severity == "critical").scalar() or 0
    risks_open = db.query(func.count(Risk.id)).filter(Risk.status == "open").scalar() or 0
    scans_last_30d = db.query(func.count(Scan.id)).filter(Scan.created_at >= thirty_days_ago).scalar() or 0
    agent_runs_total = db.query(func.count(AgentRun.id)).scalar() or 0

    # Compliance scores per framework
    assessments = db.query(FrameworkAssessment).order_by(FrameworkAssessment.assessed_at.desc()).limit(20).all()
    scores: Dict[str, float] = {}
    for a in assessments:
        key = a.framework.value if hasattr(a.framework, "value") else str(a.framework)
        if key not in scores:
            scores[key] = a.overall_score or 0.0
    avg_compliance = sum(scores.values()) / len(scores) if scores else 0.0

    # Recent data for activity feeds
    recent_scans_raw = db.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()
    recent_scans = [
        {"id": s.id, "client_id": s.client_id, "scan_type": s.scan_type.value if hasattr(s.scan_type, "value") else s.scan_type,
         "status": s.status.value if hasattr(s.status, "value") else s.status,
         "framework": s.framework.value if hasattr(s.framework, "value") else s.framework,
         "created_at": s.created_at.isoformat() if s.created_at else None,
         "summary": s.summary}
        for s in recent_scans_raw
    ]

    recent_risks_raw = db.query(Risk).filter(Risk.status == "open").order_by(Risk.created_at.desc()).limit(5).all()
    recent_risks = [
        {"id": r.id, "client_id": r.client_id, "title": r.title,
         "risk_level": r.risk_level.value if hasattr(r.risk_level, "value") else r.risk_level,
         "risk_score": r.risk_score, "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in recent_risks_raw
    ]

    recent_findings_raw = db.query(Finding).filter(
        Finding.status == "open", Finding.severity.in_(["critical", "high"])
    ).order_by(Finding.created_at.desc()).limit(5).all()
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
        risks_open=risks_open,
        scans_last_30d=scans_last_30d,
        compliance_scores=scores,
        posture_health=posture,
        recent_scans=recent_scans,
        recent_risks=recent_risks,
        recent_findings=recent_findings,
        agent_runs_total=agent_runs_total,
    )
