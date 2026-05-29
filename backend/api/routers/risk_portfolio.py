"""Risk portfolio dashboard — FAIR-lite quantification of the Risk Register.

Returns financial exposure (total, net, per-domain) plus a per-risk table
shape suitable for the risk-focused dashboard. This is *not* the legacy
issues-flavoured /risk-overview endpoint — that one stays untouched.

ALE model (FAIR-lite):
  magnitude = BASE_PER_SEV[level] * (impact / 5)
  frequency = likelihood / 5         (annual events)
  ale       = magnitude * frequency
  ale range = [ale * 0.5, ale * 2.0]  (10th-90th percentile band)

Status discount applied to net exposure:
  open / in_progress / accepted    → 1.00
  compensating_control             → 0.50
  transferred                      → 0.20
  remediated / closed              → 0.00
"""
from __future__ import annotations
import math
from collections import defaultdict
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.models.models import Risk, Client
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/risk-portfolio", tags=["risk-portfolio"])


# ── FAIR-lite constants ──────────────────────────────────────────────────────

BASE_PER_SEV = {
    "critical": 1_000_000,
    "high":     250_000,
    "medium":   50_000,
    "low":      10_000,
}

# Mitigation factor — how much of the ALE remains exposed given the current
# remediation status. Open/accepted carry full exposure; transferred carries
# only residual risk; remediated/closed carry none.
STATUS_FACTOR = {
    "open":                  1.00,
    "in_progress":           0.75,
    "compensating_control":  0.50,
    "accepted":              1.00,
    "transferred":           0.20,
    "remediated":            0.00,
    "mitigated":             0.00,  # legacy synonym
    "closed":                0.00,
}

# Canonical risk domains — we normalise risk.category onto this set so the
# domain bar chart has stable labels.
_DOMAIN_KEYWORDS: List[tuple] = [
    ("Identity",        ("identity", "iam", "mfa", "access", "auth", "rbac", "okta", "entra")),
    ("OT Security",     ("ot ", "ics", "scada", "industrial", "purdue", "operational tech")),
    ("SOC",             ("soc ", "siem", "detection", "incident", "alert", "monitoring")),
    ("Data Protection", ("data", "encryption", "privacy", "dlp", "gdpr", "ccpa", "classification")),
    ("Cloud Security",  ("cloud", "cspm", "cnapp", "cwpp", "aws", "azure", "gcp", "k8s", "kubernetes")),
    ("Vulnerability",   ("vulnerability", "cve", "patch", "cvss", "exploit")),
    ("Network",         ("network", "firewall", "nsg", "segmentation", "vpn")),
    ("Supply Chain",    ("supply", "sbom", "third-party", "third party", "vendor")),
    ("AppSec",          ("appsec", "sast", "dast", "sca", "application", "xss", "sqli")),
    ("Compliance",      ("compliance", "audit", "nist", "iso", "soc2", "pci", "cmmc")),
]


def _normalize_domain(category: str | None) -> str:
    if not category:
        return "Uncategorized"
    lc = category.lower()
    for label, kws in _DOMAIN_KEYWORDS:
        for kw in kws:
            if kw in lc:
                return label
    return category or "Uncategorized"


def _lvl(r: Risk) -> str:
    return r.risk_level.value if hasattr(r.risk_level, "value") else str(r.risk_level)


def _ale_for(risk: Risk) -> float:
    base = BASE_PER_SEV.get(_lvl(risk), 50_000)
    impact = max(1, min(5, int(risk.impact or 3)))
    likelihood = max(1, min(5, int(risk.likelihood or 3)))
    magnitude = base * (impact / 5.0)
    frequency = likelihood / 5.0
    return round(magnitude * frequency, 2)


def _status(r: Risk) -> str:
    return (r.status or "open").lower()


@router.get("/")
async def get_risk_portfolio(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> Dict[str, Any]:
    if not db.query(Client.id).filter(Client.id == client_id).first():
        raise HTTPException(status_code=404, detail="Client not found")

    risks = db.query(Risk).filter(Risk.client_id == client_id).all()

    total_exposure = 0.0
    net_exposure = 0.0
    open_critical_high = 0
    open_critical = 0
    open_high = 0
    by_domain_exposure: Dict[str, float] = defaultdict(float)
    by_domain_count: Dict[str, int] = defaultdict(int)
    rows: List[Dict[str, Any]] = []

    # Frequency aggregator for breach probability — sum of likelihood-derived
    # event rates over open critical+high risks.
    annual_event_rate = 0.0

    for r in risks:
        lv = _lvl(r)
        status = _status(r)
        ale = _ale_for(r)
        factor = STATUS_FACTOR.get(status, 1.0)
        net_ale = ale * factor
        domain = _normalize_domain(r.category)

        total_exposure += ale
        net_exposure += net_ale
        by_domain_exposure[domain] += net_ale
        by_domain_count[domain] += 1

        if status in ("open", "in_progress", "accepted") and lv in ("critical", "high"):
            open_critical_high += 1
            if lv == "critical": open_critical += 1
            else:                open_high += 1
            # Each open critical/high contributes its likelihood-derived rate.
            # Critical risks carry 3x weight to reflect blast radius.
            weight = 3.0 if lv == "critical" else 1.0
            annual_event_rate += (max(1, min(5, int(r.likelihood or 3))) / 5.0) * weight

        rows.append({
            "id": r.id,
            "title": r.title,
            "severity": lv,
            "domain": domain,
            "category": r.category,
            "impact": int(r.impact or 3),
            "likelihood": int(r.likelihood or 3),
            "risk_score": round(float(r.risk_score or 0), 2),
            "ale": round(ale, 2),
            "ale_low": round(ale * 0.5, 2),
            "ale_high": round(ale * 2.0, 2),
            "net_ale": round(net_ale, 2),
            "remediation_status": status,
            "finding_ids": list(r.finding_ids or []),
            "finding_count": len(r.finding_ids or []),
            "owner": r.owner,
            "due_date": r.due_date.isoformat() if r.due_date else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })

    # 30-day breach probability — Poisson tail: P(>=1 event in 30 days)
    # given annual event rate. Bounded to [0, 99%] so 0 risks → 0%, lots of
    # critical/high → asymptotic 99%.
    rate_30d = annual_event_rate * (30.0 / 365.0)
    breach_prob_30d = 0.0 if annual_event_rate == 0 else min(0.99, 1 - math.exp(-rate_30d))

    mitigated_pct = 0
    if total_exposure > 0:
        mitigated_pct = int(round((1 - net_exposure / total_exposure) * 100))

    by_domain_sorted = sorted(
        [
            {
                "domain": d,
                "exposure": round(by_domain_exposure[d], 2),
                "count": by_domain_count[d],
            }
            for d in by_domain_exposure
        ],
        key=lambda x: x["exposure"], reverse=True,
    )

    return {
        "total_exposure": round(total_exposure, 2),
        "net_exposure": round(net_exposure, 2),
        "mitigated_pct": mitigated_pct,
        "open_critical_high": open_critical_high,
        "open_critical": open_critical,
        "open_high": open_high,
        "breach_probability_30d": round(breach_prob_30d, 4),
        "annual_event_rate": round(annual_event_rate, 3),
        "by_domain": by_domain_sorted,
        "risks": sorted(rows, key=lambda r: r["net_ale"], reverse=True),
    }
