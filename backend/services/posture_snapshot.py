"""Take a point-in-time posture snapshot for a client and persist it."""
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func


def take_snapshot(db: Session, client_id: str) -> "PostureSnapshot":
    """Capture current metrics for client_id and insert a PostureSnapshot row."""
    from api.models.models import (
        PostureSnapshot, Finding, Scan, Risk, AgentRun, FrameworkAssessment
    )
    from sqlalchemy import func

    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    # Finding counts
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(
        Scan.client_id == client_id, Finding.status == "open"
    )
    open_findings = q.count()
    critical = q.filter(Finding.severity == "critical").count()
    high = q.filter(Finding.severity == "high").count()
    medium = q.filter(Finding.severity == "medium").count()
    low = q.filter(Finding.severity == "low").count()

    # Open risks
    open_risks = db.query(func.count(Risk.id)).filter(
        Risk.client_id == client_id, Risk.status == "open"
    ).scalar() or 0

    # MTTR — findings closed in last 90 days
    mttr_critical = _calc_mttr(db, client_id, "critical")
    mttr_high = _calc_mttr(db, client_id, "high")

    # Compliance score
    assessment = db.query(FrameworkAssessment).filter(
        FrameworkAssessment.client_id == client_id
    ).order_by(FrameworkAssessment.assessed_at.desc()).first()
    compliance_score = assessment.overall_score if assessment else None

    # Activity counts (last 30 days)
    scan_count = db.query(func.count(Scan.id)).filter(
        Scan.client_id == client_id,
        Scan.created_at >= thirty_days_ago
    ).scalar() or 0
    agent_runs = db.query(func.count(AgentRun.id)).filter(
        AgentRun.client_id == client_id,
        AgentRun.started_at >= thirty_days_ago
    ).scalar() or 0

    snap = PostureSnapshot(
        client_id=client_id,
        open_findings=open_findings,
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        low_findings=low,
        open_risks=open_risks,
        mttr_critical_hours=mttr_critical,
        mttr_high_hours=mttr_high,
        compliance_score=compliance_score,
        scan_count_30d=scan_count,
        agent_runs_30d=agent_runs,
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)
    return snap


def _calc_mttr(db, client_id: str, severity: str) -> float | None:
    """Average hours between finding created_at and remediated_at for severity."""
    from api.models.models import Finding, Scan
    from sqlalchemy import text
    rows = (
        db.query(Finding.created_at, Finding.remediated_at)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.severity == severity,
            Finding.status == "remediated",
            Finding.remediated_at.isnot(None),
        )
        .all()
    )
    if not rows:
        return None
    durations = []
    for created, remediated in rows:
        if created and remediated:
            if hasattr(created, 'timestamp'):
                diff = (remediated - created).total_seconds() / 3600
            else:
                diff = 0
            if diff >= 0:
                durations.append(diff)
    return round(sum(durations) / len(durations), 2) if durations else None
