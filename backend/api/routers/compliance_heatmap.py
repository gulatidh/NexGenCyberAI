"""Compliance heatmap — framework × domain pass-rate matrix for a client."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Dict, Any
from collections import defaultdict

from api.models.models import FrameworkControl, FrameworkAssessment
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/compliance/heatmap", tags=["compliance"])


@router.get("/")
async def get_compliance_heatmap(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> Dict[str, Any]:
    """Return a framework × domain matrix with pass rates.

    Shape:
    {
      "frameworks": ["nist_csf", "iso_27001", ...],
      "domains": ["Access Control", "Logging", ...],
      "matrix": {
        "nist_csf": {
          "Access Control": {"total": 12, "passed": 8, "failed": 4, "rate": 0.67},
          ...
        }
      },
      "summary": {
        "nist_csf": {"overall_score": 72.5, "controls_total": 100, "controls_passed": 72},
        ...
      }
    }
    """
    # Get all assessments for this client (latest per framework)
    assessments = (
        db.query(FrameworkAssessment)
        .filter(FrameworkAssessment.client_id == client_id)
        .order_by(FrameworkAssessment.assessed_at.desc())
        .all()
    )
    latest: Dict[str, FrameworkAssessment] = {}
    for a in assessments:
        fw = a.framework.value if hasattr(a.framework, "value") else str(a.framework)
        if fw not in latest:
            latest[fw] = a

    # Get all framework controls with domain info
    controls = db.query(FrameworkControl).all()
    # Build control_id → domain map per framework
    ctrl_domain: Dict[str, Dict[str, str]] = defaultdict(dict)  # fw → {ctrl_id: domain}
    all_domains: set = set()
    for c in controls:
        fw = c.framework.value if hasattr(c.framework, "value") else str(c.framework)
        domain = c.domain or "General"
        ctrl_domain[fw][c.control_id] = domain
        all_domains.add(domain)

    # Build matrix
    matrix: Dict[str, Dict[str, Dict]] = {}
    for fw, assessment in latest.items():
        control_results = assessment.control_results or {}
        domain_stats: Dict[str, Dict] = defaultdict(lambda: {"total": 0, "passed": 0})
        fw_ctrl_map = ctrl_domain.get(fw, {})
        for ctrl_id, result in control_results.items():
            domain = fw_ctrl_map.get(ctrl_id, "General")
            domain_stats[domain]["total"] += 1
            status = result.get("status", "") if isinstance(result, dict) else str(result)
            if status in ("passed", "pass", "compliant"):
                domain_stats[domain]["passed"] += 1
        # Compute rates
        matrix[fw] = {}
        for domain, stats in domain_stats.items():
            t = stats["total"]
            p = stats["passed"]
            matrix[fw][domain] = {
                "total": t,
                "passed": p,
                "failed": t - p,
                "rate": round(p / t, 2) if t > 0 else 0.0,
            }

    frameworks = sorted(latest.keys())
    domains = sorted(all_domains)

    return {
        "frameworks": frameworks,
        "domains": domains,
        "matrix": matrix,
        "summary": {
            fw: {
                "overall_score": a.overall_score,
                "controls_total": a.controls_total,
                "controls_passed": a.controls_passed,
            }
            for fw, a in latest.items()
        },
    }
