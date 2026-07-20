"""Multi-client comparison — side-by-side posture metrics."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from api.models.models import Client, Finding, Scan, Risk, FrameworkAssessment
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/compare", tags=["clients"])


@router.get("/")
async def compare_clients(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """Return posture metrics for all active clients side-by-side."""
    clients = db.query(Client).filter(Client.deleted_at.is_(None)).all()
    result = []
    for client in clients:
        # Finding counts by severity (open, non-suppressed canonical only)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        findings = (
            db.query(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .filter(
                Scan.client_id == client.id,
                Finding.status == "open",
                Finding.duplicate_of_id.is_(None),
                Finding.suppressed_at.is_(None),
            )
            .all()
        )
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1

        # Risk score (average of open risks)
        risks = db.query(Risk).filter(
            Risk.client_id == client.id,
            Risk.status == "open",
        ).all()
        avg_risk = round(sum(r.risk_score or 0 for r in risks) / len(risks), 1) if risks else 0

        # Latest framework assessment score
        latest_fw = (
            db.query(FrameworkAssessment)
            .filter(FrameworkAssessment.client_id == client.id)
            .order_by(FrameworkAssessment.assessed_at.desc())
            .first()
        )
        fw_score = round(latest_fw.overall_score or 0, 1) if latest_fw else None
        fw_name = (
            (latest_fw.framework.value if hasattr(latest_fw.framework, "value") else str(latest_fw.framework))
            if latest_fw else None
        )

        # Last scan date
        last_scan = (
            db.query(Scan)
            .filter(Scan.client_id == client.id, Scan.status == "completed")
            .order_by(Scan.completed_at.desc())
            .first()
        )

        result.append({
            "id": client.id,
            "name": client.name,
            "industry": getattr(client, "industry", None),
            "findings": counts,
            "total_open": sum(counts.values()),
            "avg_risk_score": avg_risk,
            "framework_score": fw_score,
            "framework_name": fw_name,
            "last_scan_at": last_scan.completed_at.isoformat() if last_scan and last_scan.completed_at else None,
            "open_risks": len(risks),
        })

    # Sort by total open findings descending
    result.sort(key=lambda x: x["total_open"], reverse=True)
    return result
