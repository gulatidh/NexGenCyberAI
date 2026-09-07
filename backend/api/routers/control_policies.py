"""
Security Control Policies — user-defined rules evaluated live against open findings.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional, List
from pydantic import BaseModel
import json
import uuid

from db.database import get_db
from core.security import get_current_user
from api.models.models import ControlPolicy, Finding, Scan, Connector, Asset

router = APIRouter(tags=["control-policies"])

RISK_TAG_OPTIONS = [
    "lateral_movement", "data_exposure", "privilege_escalation",
    "initial_access", "credential_theft", "network_exposure",
    "misconfiguration", "vulnerable_software", "identity_risk",
    "supply_chain", "ransomware_path", "exfiltration",
]


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    severity: str = "high"
    category: Optional[str] = None
    match_title: Optional[str] = None
    match_severity: Optional[str] = None
    match_asset_class: Optional[str] = None
    match_cve: Optional[str] = None
    match_resource_type: Optional[str] = None   # legacy compat
    match_resource_types: List[str] = []         # multi-type scoping
    match_connector_type: Optional[str] = None
    framework: Optional[str] = None
    framework_control_id: Optional[str] = None
    risk_tags: Optional[List[str]] = None


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    match_title: Optional[str] = None
    match_severity: Optional[str] = None
    match_asset_class: Optional[str] = None
    match_cve: Optional[str] = None
    match_resource_type: Optional[str] = None   # legacy compat
    match_resource_types: Optional[List[str]] = None  # multi-type scoping
    match_connector_type: Optional[str] = None
    framework: Optional[str] = None
    framework_control_id: Optional[str] = None
    risk_tags: Optional[List[str]] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _live_scan_ids(db: Session, client_id: str) -> List[str]:
    rows = (
        db.query(Scan.id)
        .join(Connector, Scan.connector_id == Connector.id)
        .filter(Connector.client_id == client_id, Scan.is_live == True)
        .all()
    )
    return [r[0] for r in rows]


def _get_resource_types(policy: ControlPolicy) -> List[str]:
    """Return the effective resource type list for a policy (multi takes precedence)."""
    if policy.match_resource_types:
        try:
            types = json.loads(policy.match_resource_types)
            if isinstance(types, list) and types:
                return types
        except Exception:
            pass
    if policy.match_resource_type:
        return [policy.match_resource_type]
    return []


def _apply_resource_type_filter(q, resource_types: List[str]):
    if resource_types:
        q = q.filter(Finding.resource_type.in_(resource_types))
    return q


def _evaluate_policy(db: Session, policy: ControlPolicy, client_id: str):
    scan_ids = _live_scan_ids(db, client_id)
    if not scan_ids:
        return 0, 0

    q = db.query(Finding).filter(
        Finding.scan_id.in_(scan_ids),
        Finding.status == "open",
    )
    if policy.match_title:
        q = q.filter(Finding.title.ilike(f"%{policy.match_title}%"))
    if policy.match_severity:
        q = q.filter(Finding.severity == policy.match_severity)
    if policy.match_cve:
        q = q.filter(
            or_(
                Finding.cve_id.ilike(f"%{policy.match_cve}%"),
                Finding.cve_ids.ilike(f"%{policy.match_cve}%"),
            )
        )
    q = _apply_resource_type_filter(q, _get_resource_types(policy))
    if policy.match_connector_type:
        q = q.filter(
            Finding.scan_id.in_(
                db.query(Scan.id)
                .join(Connector, Scan.connector_id == Connector.id)
                .filter(
                    Connector.client_id == client_id,
                    Connector.connector_type == policy.match_connector_type,
                    Scan.is_live == True,
                )
                .scalar_subquery()
            )
        )

    findings = q.all()
    issue_count = len(findings)
    affected_assets = len({f.resource_id for f in findings if f.resource_id})
    return issue_count, affected_assets


def _policy_to_dict(p: ControlPolicy, issue_count: int = 0, affected_assets: int = 0) -> dict:
    return {
        "id": p.id,
        "client_id": p.client_id,
        "name": p.name,
        "description": p.description,
        "severity": p.severity,
        "category": p.category,
        "status": p.status,
        "match_title": p.match_title,
        "match_severity": p.match_severity,
        "match_asset_class": p.match_asset_class,
        "match_cve": p.match_cve,
        "match_resource_type": p.match_resource_type,
        "match_resource_types": json.loads(p.match_resource_types) if p.match_resource_types else [],
        "match_connector_type": p.match_connector_type,
        "framework": p.framework,
        "framework_control_id": p.framework_control_id,
        "risk_tags": json.loads(p.risk_tags) if p.risk_tags else [],
        "created_by": p.created_by,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
        "issue_count": issue_count,
        "affected_assets": affected_assets,
    }


# ── Preview (dry-run, no DB write) — must come before {policy_id} routes ─────

@router.post("/clients/{client_id}/control-policies/preview")
def preview_policy(
    client_id: str,
    body: PolicyCreate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Dry-run evaluation: count matching findings without creating a policy."""
    temp = ControlPolicy(
        id="__preview__",
        client_id=client_id,
        name=body.name or "",
        status="active",
        match_title=body.match_title,
        match_severity=body.match_severity,
        match_asset_class=body.match_asset_class,
        match_cve=body.match_cve,
        match_resource_type=None,
        match_resource_types=json.dumps(body.match_resource_types or []),
        match_connector_type=body.match_connector_type,
    )
    issue_count, affected_assets = _evaluate_policy(db, temp, client_id)
    return {"issue_count": issue_count, "affected_assets": affected_assets}


# ── Framework controls picker (global — no client_id, must come before {policy_id} routes) ──

@router.get("/control-policies/framework-controls/")
def browse_framework_controls(
    framework: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(500, le=2000),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return FrameworkControl rows for the policy creation picker."""
    from api.models.models import FrameworkControl
    q = db.query(FrameworkControl)
    if framework:
        q = q.filter(FrameworkControl.framework == framework)
    if domain:
        q = q.filter(FrameworkControl.domain == domain)
    if search:
        q = q.filter(
            or_(
                FrameworkControl.control_id.ilike(f"%{search}%"),
                FrameworkControl.title.ilike(f"%{search}%"),
            )
        )
    rows = q.order_by(FrameworkControl.framework, FrameworkControl.control_id).limit(limit).all()
    return [
        {
            "id": r.id,
            "framework": r.framework.value if hasattr(r.framework, "value") else str(r.framework),
            "control_id": r.control_id,
            "domain": r.domain,
            "title": r.title,
            "description": r.description,
        }
        for r in rows
    ]


# ── Client-scoped endpoints ───────────────────────────────────────────────────

@router.get("/clients/{client_id}/control-policies/")
def list_policies(
    client_id: str,
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    q = db.query(ControlPolicy).filter(ControlPolicy.client_id == client_id)
    if status:
        q = q.filter(ControlPolicy.status == status)
    if severity:
        q = q.filter(ControlPolicy.severity == severity)
    if category:
        q = q.filter(ControlPolicy.category == category)
    policies = q.order_by(ControlPolicy.severity, ControlPolicy.name).all()

    result = []
    for p in policies:
        count, assets = _evaluate_policy(db, p, client_id) if p.status == "active" else (0, 0)
        result.append(_policy_to_dict(p, count, assets))
    return result


@router.post("/clients/{client_id}/control-policies/")
def create_policy(
    client_id: str,
    body: PolicyCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    created_by = (
        user.get("preferred_username") or user.get("upn")
        or user.get("email") or user.get("unique_name", "")
    )
    p = ControlPolicy(
        id=str(uuid.uuid4()),
        client_id=client_id,
        name=body.name,
        description=body.description,
        severity=body.severity,
        category=body.category,
        status="active",
        match_title=body.match_title,
        match_severity=body.match_severity,
        match_asset_class=body.match_asset_class,
        match_cve=body.match_cve,
        match_resource_type=body.match_resource_type,
        match_resource_types=json.dumps(body.match_resource_types or []),
        match_connector_type=body.match_connector_type,
        framework=body.framework,
        framework_control_id=body.framework_control_id,
        risk_tags=json.dumps(body.risk_tags or []),
        created_by=created_by,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    count, assets = _evaluate_policy(db, p, client_id)
    return _policy_to_dict(p, count, assets)


@router.get("/clients/{client_id}/control-policies/{policy_id}")
def get_policy(
    client_id: str,
    policy_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    p = db.query(ControlPolicy).filter(
        ControlPolicy.id == policy_id, ControlPolicy.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(404, "Policy not found")
    count, assets = _evaluate_policy(db, p, client_id) if p.status == "active" else (0, 0)
    return _policy_to_dict(p, count, assets)


@router.patch("/clients/{client_id}/control-policies/{policy_id}")
def update_policy(
    client_id: str,
    policy_id: str,
    body: PolicyUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    p = db.query(ControlPolicy).filter(
        ControlPolicy.id == policy_id, ControlPolicy.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(404, "Policy not found")
    for field in ["name", "description", "severity", "category",
                  "match_title", "match_severity", "match_asset_class",
                  "match_cve", "match_resource_type", "match_connector_type",
                  "framework", "framework_control_id"]:
        val = getattr(body, field)
        if val is not None:
            setattr(p, field, val)
    if body.risk_tags is not None:
        p.risk_tags = json.dumps(body.risk_tags)
    if body.match_resource_types is not None:
        p.match_resource_types = json.dumps(body.match_resource_types)
    from datetime import datetime
    p.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(p)
    count, assets = _evaluate_policy(db, p, client_id) if p.status == "active" else (0, 0)
    return _policy_to_dict(p, count, assets)


@router.post("/clients/{client_id}/control-policies/{policy_id}/toggle")
def toggle_policy(
    client_id: str,
    policy_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    p = db.query(ControlPolicy).filter(
        ControlPolicy.id == policy_id, ControlPolicy.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(404, "Policy not found")
    p.status = "disabled" if p.status == "active" else "active"
    from datetime import datetime
    p.updated_at = datetime.utcnow()
    db.commit()
    count, assets = _evaluate_policy(db, p, client_id) if p.status == "active" else (0, 0)
    return _policy_to_dict(p, count, assets)


@router.delete("/clients/{client_id}/control-policies/{policy_id}")
def delete_policy(
    client_id: str,
    policy_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    p = db.query(ControlPolicy).filter(
        ControlPolicy.id == policy_id, ControlPolicy.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(404, "Policy not found")
    db.delete(p)
    db.commit()
    return {"ok": True}


@router.get("/clients/{client_id}/control-policies/{policy_id}/issues")
def get_policy_issues(
    client_id: str,
    policy_id: str,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    p = db.query(ControlPolicy).filter(
        ControlPolicy.id == policy_id, ControlPolicy.client_id == client_id
    ).first()
    if not p:
        raise HTTPException(404, "Policy not found")
    if p.status == "disabled":
        return {"policy_id": policy_id, "findings": [], "total": 0}

    scan_ids = _live_scan_ids(db, client_id)
    if not scan_ids:
        return {"policy_id": policy_id, "findings": [], "total": 0}

    q = db.query(Finding).filter(
        Finding.scan_id.in_(scan_ids),
        Finding.status == "open",
    )
    if p.match_title:
        q = q.filter(Finding.title.ilike(f"%{p.match_title}%"))
    if p.match_severity:
        q = q.filter(Finding.severity == p.match_severity)
    if p.match_cve:
        q = q.filter(
            or_(
                Finding.cve_id.ilike(f"%{p.match_cve}%"),
                Finding.cve_ids.ilike(f"%{p.match_cve}%"),
            )
        )
    q = _apply_resource_type_filter(q, _get_resource_types(p))
    if p.match_connector_type:
        q = q.filter(
            Finding.scan_id.in_(
                db.query(Scan.id)
                .join(Connector, Scan.connector_id == Connector.id)
                .filter(
                    Connector.client_id == client_id,
                    Connector.connector_type == p.match_connector_type,
                    Scan.is_live == True,
                )
                .scalar_subquery()
            )
        )

    total = q.count()
    findings = q.order_by(Finding.severity).limit(limit).all()
    return {
        "policy_id": policy_id,
        "total": total,
        "findings": [
            {
                "id": f.id, "title": f.title, "severity": f.severity,
                "resource_id": f.resource_id, "resource_type": f.resource_type,
                "cve_id": f.cve_id, "cvss_score": f.cvss_score,
                "status": f.status, "scan_id": f.scan_id,
            }
            for f in findings
        ],
    }


@router.get("/clients/{client_id}/control-policies/meta/options")
def get_policy_options(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    scan_ids = _live_scan_ids(db, client_id)
    severities = ["critical", "high", "medium", "low", "info"]
    asset_classes = [
        r[0] for r in db.query(Asset.asset_class).filter(
            Asset.client_id == client_id, Asset.asset_class.isnot(None)
        ).distinct().all() if r[0]
    ]
    resource_types = [
        r[0] for r in db.query(Finding.resource_type).filter(
            Finding.scan_id.in_(scan_ids), Finding.resource_type.isnot(None)
        ).distinct().limit(100).all() if r[0]
    ] if scan_ids else []
    connectors = db.query(Connector).filter(Connector.client_id == client_id).all()

    return {
        "severities": severities,
        "asset_classes": sorted(asset_classes),
        "resource_types": sorted(resource_types),
        "connector_types": list({c.connector_type.value if hasattr(c.connector_type, "value") else str(c.connector_type) for c in connectors}),
        "risk_tags": RISK_TAG_OPTIONS,
        "categories": ["Identity", "Network", "Data", "Compute", "Application", "Supply Chain", "Compliance", "Other"],
    }
