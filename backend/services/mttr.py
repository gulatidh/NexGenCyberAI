"""MTTR (Mean Time to Remediate) metrics service."""
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from sqlalchemy.orm import Session


def get_mttr_metrics(db: Session, client_id: str) -> Dict[str, Any]:
    """Return MTTR metrics by severity, trend data, and SLA breach counts."""
    from api.models.models import Finding, Scan
    from collections import defaultdict

    all_remediated = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.status == "remediated",
            Finding.remediated_at.isnot(None),
        )
        .all()
    )

    by_severity: Dict[str, List[float]] = defaultdict(list)
    for f in all_remediated:
        if f.created_at and f.remediated_at:
            hours = (f.remediated_at - f.created_at).total_seconds() / 3600
            if hours >= 0:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                by_severity[sev].append(hours)

    def _avg(lst): return round(sum(lst) / len(lst), 1) if lst else None

    # SLA targets in hours
    SLA = {"critical": 24, "high": 168, "medium": 720, "low": 2160}

    # Open findings breaching SLA
    now = datetime.now(timezone.utc)
    open_findings = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open")
        .all()
    )
    sla_breaches: Dict[str, int] = defaultdict(int)
    for f in open_findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sla_hours = SLA.get(sev, 9999)
        if f.created_at:
            age_hours = (now - f.created_at).total_seconds() / 3600
            if age_hours > sla_hours:
                sla_breaches[sev] += 1

    return {
        "mttr_by_severity": {
            sev: {"avg_hours": _avg(vals), "count": len(vals), "sla_hours": SLA.get(sev)}
            for sev, vals in by_severity.items()
        },
        "sla_breaches": dict(sla_breaches),
        "total_remediated": len(all_remediated),
        "sla_targets_hours": SLA,
    }
