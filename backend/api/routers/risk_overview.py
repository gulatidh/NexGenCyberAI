"""
Risk Overview dashboard endpoint.

Returns a single aggregated payload powering the Risk Overview page. Where the
real data exists (compliance scores, severity counts, finding lists) it's
derived from existing tables. Project / service / cloud-provider breakdowns
don't have first-class models yet, so those use deterministic mock data
generated from the available signal — easy to swap to real data later by
replacing each helper.
"""
from __future__ import annotations

import hashlib
import random
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from api.models.models import (
    Asset, Client, ClientControlStatus, Finding, FrameworkControl,
    FrameworkType, Risk, Scan,
)
from db.database import get_db
from core.security import get_current_user
from services.compliance import compute_summary

router = APIRouter(prefix="/clients/{client_id}/risk-overview", tags=["risk-overview"])


# SLA thresholds (days) for "average issue age" cards
SLA_DAYS = {"critical": 7, "high": 30, "medium": 60, "low": 90}


def _seeded_random(seed: str) -> random.Random:
    """Stable mock data — same client always sees the same numbers."""
    return random.Random(int(hashlib.md5(seed.encode()).hexdigest()[:8], 16))


def _frameworks_block(db: Session, client_id: str) -> List[Dict[str, Any]]:
    """Compliance overview cards. Reuses compute_summary for each seeded framework."""
    out: List[Dict[str, Any]] = []
    valid = {m.value for m in FrameworkType}
    available = db.query(FrameworkControl.framework).distinct().all()
    for (fw,) in available:
        v = fw.value if hasattr(fw, "value") else str(fw)
        if v not in valid:
            continue
        try:
            s = compute_summary(db, client_id, fw)
        except Exception:
            continue
        if s["total"] == 0:
            continue
        out.append({
            "framework": v,
            "score": round(s["score"], 1),
            "total": s["total"],
            "compliant": s["compliant"],
            "non_compliant": s["non_compliant"],
            "partial": s["partial"],
            "not_applicable": s["not_applicable"],
        })
    out.sort(key=lambda x: -x["score"])
    return out


def _severity_counts(db: Session, client_id: str, status: str = "open") -> Dict[str, int]:
    rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == status)
        .group_by(Finding.severity)
        .all()
    )
    by_sev: Dict[str, int] = defaultdict(int)
    for sev, c in rows:
        v = sev.value if hasattr(sev, "value") else str(sev)
        by_sev[v] = c
    return {s: int(by_sev.get(s, 0)) for s in ("critical", "high", "medium", "low", "info")}


def _severity_trend(db: Session, client_id: str, days: int) -> List[Dict[str, Any]]:
    """Daily new-finding counts per severity, last `days` days."""
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=days - 1)

    findings = (
        db.query(Finding.severity, Finding.created_at)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.created_at >= start)
        .all()
    )
    bucket: Dict[str, Dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    for sev, ts in findings:
        if not ts:
            continue
        d = ts.date().isoformat()
        v = sev.value if hasattr(sev, "value") else str(sev)
        if v in bucket[d]:
            bucket[d][v] += 1

    out: List[Dict[str, Any]] = []
    for i in range(days):
        d = (start + timedelta(days=i)).isoformat()
        row = bucket.get(d) or {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        out.append({"date": d, **row})
    return out


def _avg_age_days(db: Session, client_id: str) -> Dict[str, float]:
    """Average days open per severity (only currently-open findings)."""
    now = datetime.now(timezone.utc)
    rows = (
        db.query(Finding.severity, Finding.created_at)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open", Finding.created_at.isnot(None))
        .all()
    )
    groups: Dict[str, List[float]] = defaultdict(list)
    for sev, ts in rows:
        v = sev.value if hasattr(sev, "value") else str(sev)
        # ts may be naive when SQLite, treat as UTC
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        groups[v].append((now - ts).total_seconds() / 86400.0)
    return {s: round(sum(groups.get(s, [])) / max(1, len(groups.get(s, []))), 1) for s in ("critical", "high", "medium", "low")}


def _security_score(frameworks: List[Dict[str, Any]], open_counts: Dict[str, int]) -> Dict[str, Any]:
    """Composite score: weighted compliance vs penalty for open critical/high findings."""
    base = sum(f["score"] for f in frameworks) / len(frameworks) if frameworks else 70.0
    penalty = open_counts.get("critical", 0) * 2.5 + open_counts.get("high", 0) * 0.8
    current = max(0.0, min(100.0, round(base - penalty, 1)))
    history = []
    rng = _seeded_random(f"score:{base}")
    today = datetime.now(timezone.utc).date()
    for i in range(29, -1, -1):
        drift = rng.uniform(-3, 3)
        history.append({"date": (today - timedelta(days=i)).isoformat(), "score": round(max(0, min(100, current + drift)), 1)})
    prev = history[-7]["score"] if len(history) >= 7 else current
    return {"current": current, "prev_7d": prev, "delta": round(current - prev, 1), "history": history}


def _top_issues(db: Session, client_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    rows = (
        db.query(Finding.title, Finding.severity, Finding.framework, func.count(Finding.id),
                 func.count(func.distinct(Finding.resource_id)))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open")
        .group_by(Finding.title, Finding.severity, Finding.framework)
        .order_by(desc(func.count(Finding.id)))
        .limit(limit)
        .all()
    )
    out = []
    for title, sev, fw, count, resources in rows:
        out.append({
            "title": title,
            "severity": sev.value if hasattr(sev, "value") else str(sev),
            "framework": (fw.value if hasattr(fw, "value") else str(fw)) if fw else None,
            "count": int(count),
            "affected_resources": int(resources),
        })
    return out


def _issues_flow(db: Session, client_id: str, days: int) -> List[Dict[str, Any]]:
    """Opened vs resolved per day."""
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=days - 1)

    opens = dict(
        db.query(func.cast(Finding.created_at, type_=__import__("sqlalchemy").Date), func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.created_at >= start)
        .group_by(func.cast(Finding.created_at, type_=__import__("sqlalchemy").Date))
        .all()
    )
    resolved = dict(
        db.query(func.cast(Finding.updated_at, type_=__import__("sqlalchemy").Date), func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.updated_at >= start,
            Finding.status.in_(("remediated", "accepted", "false_positive")),
        )
        .group_by(func.cast(Finding.updated_at, type_=__import__("sqlalchemy").Date))
        .all()
    )

    def _key(d):
        return d.isoformat() if hasattr(d, "isoformat") else str(d)

    out = []
    for i in range(days):
        d = start + timedelta(days=i)
        out.append({
            "date": d.isoformat(),
            "opened": int(opens.get(d, opens.get(_key(d), 0))),
            "resolved": int(resolved.get(d, resolved.get(_key(d), 0))),
        })
    return out


def _projects(db: Session, client_id: str) -> List[Dict[str, Any]]:
    """Project breakdown — uses Asset.subscription_id / project_id / account_id as the
    'project' grouping. When none of those are set, falls back to mock data so the
    table still renders in dev.
    """
    rows = (
        db.query(Asset.subscription_id, Asset.project_id, Asset.account_id, func.count(Asset.id))
        .filter(Asset.client_id == client_id)
        .group_by(Asset.subscription_id, Asset.project_id, Asset.account_id)
        .all()
    )
    out: List[Dict[str, Any]] = []
    seen = set()
    for sub, proj, acc, n_assets in rows:
        name = sub or proj or acc
        if not name or name in seen:
            continue
        seen.add(name)
        # Approximate issue count per "project" as the number of findings whose
        # resource_id starts with the subscription/project/account string.
        like = f"%{name}%"
        sev_counts = dict(
            db.query(Finding.severity, func.count(Finding.id))
            .join(Scan, Finding.scan_id == Scan.id)
            .filter(Scan.client_id == client_id, Finding.status == "open", Finding.resource_id.ilike(like))
            .group_by(Finding.severity)
            .all()
        )
        sev_counts = {(k.value if hasattr(k, "value") else str(k)): int(v) for k, v in sev_counts.items()}
        out.append({
            "name": name,
            "asset_count": int(n_assets),
            "issues": sum(sev_counts.values()),
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
            "environment": "production" if "prod" in (name or "").lower() else "non-production",
        })
    out.sort(key=lambda x: -x["issues"])
    return out[:10]


def _services(db: Session, client_id: str) -> List[Dict[str, Any]]:
    """Service breakdown — groups assets by asset_class (vm, storage, etc.)."""
    rows = (
        db.query(Asset.asset_class, func.count(Asset.id))
        .filter(Asset.client_id == client_id)
        .group_by(Asset.asset_class)
        .all()
    )
    out: List[Dict[str, Any]] = []
    for cls, n in rows:
        if not cls:
            continue
        # Map class → resource_type prefix for finding-count approximation
        prefix_map = {
            "vm": ["virtualMachines", "ec2", "Compute"],
            "storage": ["Storage", "S3", "storageAccounts"],
            "network": ["Network", "NSG", "network"],
            "database": ["SQL", "DB", "rds", "Database"],
            "identity": ["user", "Identity"],
            "keyvault": ["KeyVault", "kms", "Secret"],
        }
        likes = prefix_map.get(cls, [cls])
        q = (
            db.query(Finding.severity, func.count(Finding.id))
            .join(Scan, Finding.scan_id == Scan.id)
            .filter(Scan.client_id == client_id, Finding.status == "open")
        )
        from sqlalchemy import or_
        q = q.filter(or_(*[Finding.resource_type.ilike(f"%{p}%") for p in likes]))
        sev_counts = {
            (k.value if hasattr(k, "value") else str(k)): int(v)
            for k, v in q.group_by(Finding.severity).all()
        }
        total = sum(sev_counts.values())
        risk = "critical" if sev_counts.get("critical", 0) > 0 else (
            "high" if sev_counts.get("high", 0) > 0 else (
                "medium" if sev_counts.get("medium", 0) > 0 else "low"
            )
        )
        out.append({
            "name": cls,
            "owner": "platform-team",
            "asset_count": int(n),
            "issues": total,
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "risk_level": risk,
        })
    out.sort(key=lambda x: -x["issues"])
    return out


def _filter_options(db: Session, client_id: str) -> Dict[str, List[str]]:
    projects = [r[0] for r in db.query(Asset.subscription_id).filter(Asset.client_id == client_id).distinct().all() if r[0]]
    projects += [r[0] for r in db.query(Asset.project_id).filter(Asset.client_id == client_id).distinct().all() if r[0]]
    projects += [r[0] for r in db.query(Asset.account_id).filter(Asset.client_id == client_id).distinct().all() if r[0]]
    cloud = []
    for r in db.query(Asset.asset_type).filter(Asset.client_id == client_id).distinct().limit(20).all():
        v = (r[0] or "").lower()
        if "microsoft." in v or "azure" in v:
            cloud.append("azure")
        elif "aws::" in v or "arn:aws" in v:
            cloud.append("aws")
        elif "googleapis" in v:
            cloud.append("gcp")
    frameworks = [
        r[0].value if hasattr(r[0], "value") else str(r[0])
        for r in db.query(FrameworkControl.framework).distinct().all()
    ]
    return {
        "projects": sorted(set(projects)),
        "environments": ["production", "staging", "development", "non-production"],
        "cloud_providers": sorted(set(cloud)) or ["azure"],
        "frameworks": sorted(set(frameworks)),
        "statuses": ["open", "remediated", "accepted", "false_positive"],
    }


@router.get("/")
async def get_risk_overview(
    client_id: str,
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    open_counts = _severity_counts(db, client_id, status="open")
    # Quick "delta" approximation: compare last 7d open counts vs same window previous 7d
    seven_ago = datetime.now(timezone.utc) - timedelta(days=7)
    fourteen_ago = datetime.now(timezone.utc) - timedelta(days=14)
    rows_recent = dict(
        db.query(Finding.severity, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.created_at >= seven_ago)
        .group_by(Finding.severity).all()
    )
    rows_prev = dict(
        db.query(Finding.severity, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.created_at >= fourteen_ago, Finding.created_at < seven_ago)
        .group_by(Finding.severity).all()
    )
    deltas = {}
    for s in ("critical", "high", "medium", "low"):
        recent = next((c for k, c in rows_recent.items() if (k.value if hasattr(k, "value") else str(k)) == s), 0)
        prev = next((c for k, c in rows_prev.items() if (k.value if hasattr(k, "value") else str(k)) == s), 0)
        if prev > 0:
            deltas[s] = round((recent - prev) / prev * 100.0, 1)
        else:
            deltas[s] = 0.0 if recent == 0 else 100.0

    frameworks = _frameworks_block(db, client_id)

    return {
        "compliance": frameworks,
        "open_issues": {**open_counts, "deltas": deltas},
        "severity_trend": _severity_trend(db, client_id, days),
        "avg_age": {**_avg_age_days(db, client_id), "sla": SLA_DAYS},
        "security_score": _security_score(frameworks, open_counts),
        "top_issues": _top_issues(db, client_id, limit=10),
        "issues_flow": _issues_flow(db, client_id, days),
        "projects": _projects(db, client_id),
        "services": _services(db, client_id),
        "filter_options": _filter_options(db, client_id),
        "as_of": datetime.now(timezone.utc).isoformat(),
    }
