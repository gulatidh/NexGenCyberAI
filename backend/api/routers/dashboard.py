"""Dashboard summary endpoint."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from api.models.models import Client, Connector, Finding, Risk, Scan, ScanStatus, FrameworkAssessment
from api.schemas.schemas import DashboardSummary
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/", response_model=DashboardSummary)
async def get_dashboard(db: Session = Depends(get_db), _=Depends(get_current_user)):
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    total_clients = db.query(func.count(Client.id)).filter(Client.is_active == True).scalar() or 0
    active_connectors = db.query(func.count(Connector.id)).filter(Connector.status == "active").scalar() or 0
    open_findings = db.query(func.count(Finding.id)).filter(Finding.status == "open").scalar() or 0
    critical_findings = db.query(func.count(Finding.id)).filter(Finding.status == "open", Finding.severity == "critical").scalar() or 0
    risks_open = db.query(func.count(Risk.id)).filter(Risk.status == "open").scalar() or 0
    scans_last_30d = db.query(func.count(Scan.id)).filter(Scan.created_at >= thirty_days_ago).scalar() or 0

    # Compliance scores per framework
    assessments = db.query(FrameworkAssessment).order_by(FrameworkAssessment.assessed_at.desc()).limit(20).all()
    scores: Dict[str, float] = {}
    for a in assessments:
        key = a.framework.value if hasattr(a.framework, "value") else str(a.framework)
        if key not in scores:
            scores[key] = a.overall_score or 0.0

    return DashboardSummary(
        total_clients=total_clients,
        active_connectors=active_connectors,
        open_findings=open_findings,
        critical_findings=critical_findings,
        risks_open=risks_open,
        scans_last_30d=scans_last_30d,
        compliance_scores=scores,
    )
