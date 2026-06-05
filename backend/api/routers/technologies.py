"""
Technology Inventory endpoints.

A "technology" is an asset_type (e.g. Microsoft.Compute/virtualMachines,
AWS::S3::Bucket) — i.e. the product/service running, not the individual
resource. Aggregates derived from the existing Asset table where data exists,
mock-augmented for fields we don't yet track (versions, CVEs, owner team).

Designed to swap to real signal as we ingest more data — the per-row helper
functions are the pivot point.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from api.models.models import Asset, AssetStatus, Client, Connector, Finding, Project, Scan
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/technologies", tags=["technologies"])


# ── Type / Category / Subcategory taxonomy ────────────────────────────────────

# Map asset_class → broad category label + icon name (Material UI icon name)
CATEGORY_MAP: Dict[str, Dict[str, str]] = {
    "vm":        {"name": "Compute Platforms",   "icon": "Memory",        "color": "#00e5ff"},
    "storage":   {"name": "Storage & Data",      "icon": "Storage",       "color": "#ff9800"},
    "network":   {"name": "Networking",          "icon": "Lan",           "color": "#7c4dff"},
    "database":  {"name": "Database",            "icon": "Storage",       "color": "#00e676"},
    "identity":  {"name": "Identity & Access",   "icon": "Person",        "color": "#f06292"},
    "keyvault":  {"name": "Security",            "icon": "VpnKey",        "color": "#ffd54f"},
    "other":     {"name": "Other",               "icon": "Apps",          "color": "rgba(255,255,255,0.5)"},
}


# Subcategory derivation: regex-match against asset_type, return label + icon
SUBCATEGORY_RULES: List[Dict[str, Any]] = [
    {"pattern": r"virtualMachines|ec2|compute.googleapis.com/Instance", "name": "Virtual Machines",         "icon": "Computer"},
    {"pattern": r"functionApp|lambda|cloudfunctions",                   "name": "Serverless Functions",     "icon": "Bolt"},
    {"pattern": r"containerService|kubernetesCluster|aks|eks|gke",      "name": "Kubernetes & Containers",  "icon": "AllInbox"},
    {"pattern": r"appService|sites/?$|webapp|elasticbeanstalk",         "name": "App Hosting",              "icon": "Web"},
    {"pattern": r"sql/?|sqlServers|rds",                                "name": "SQL Databases",            "icon": "Storage"},
    {"pattern": r"postgres|mysql|mariaDB|documentdb|dynamodb",          "name": "NoSQL & Open-source DBs",  "icon": "Storage"},
    {"pattern": r"storageAccounts|s3|bucket",                           "name": "Object Storage",           "icon": "Storage"},
    {"pattern": r"keyvault|kms|secretsmanager",                         "name": "Secrets & KMS",            "icon": "VpnKey"},
    {"pattern": r"networkSecurityGroups|securityGroup|firewall",        "name": "Firewalls & NSGs",         "icon": "Security"},
    {"pattern": r"loadBalancer|applicationGateway|trafficManager",      "name": "Load Balancers",           "icon": "AccountTree"},
    {"pattern": r"virtualNetwork|vpc|subnet",                           "name": "Virtual Networks",         "icon": "Lan"},
    {"pattern": r"user|servicePrincipal|managedIdentity|iam",           "name": "Identities",               "icon": "Person"},
    {"pattern": r"dnsZones|publicIp|frontDoor|cdn",                     "name": "DNS, CDN & Public IPs",    "icon": "Public"},
    {"pattern": r"diagnostic|monitor|insights|cloudwatch",              "name": "Monitoring & Logs",        "icon": "Visibility"},
]


# Provider-native type → broad TYPE classification
TYPE_RULES: List[Dict[str, Any]] = [
    {"pattern": r"\bvirtualMachines\b|\bec2\b|googleapis.com/Instance",                        "type": "Compute Instance"},
    {"pattern": r"functionApp|lambda|cloudfunctions",                                          "type": "Serverless Function"},
    {"pattern": r"containerService|kubernetesCluster|aks|eks|gke",                             "type": "Container Platform"},
    {"pattern": r"appService|sites/?$|webapp|elasticbeanstalk",                                "type": "Managed App Service"},
    {"pattern": r"storageAccounts|s3|bucket|blob",                                             "type": "Object Storage"},
    {"pattern": r"sql|database|rds|cosmos|documentdb|dynamodb|postgres|mysql|mariaDB",         "type": "Managed Database"},
    {"pattern": r"keyvault|kms|secretsmanager",                                                "type": "Secrets Vault"},
    {"pattern": r"networkSecurityGroups|securityGroup|firewall",                               "type": "Security Boundary"},
    {"pattern": r"loadBalancer|applicationGateway|trafficManager|frontDoor|cdn",               "type": "Edge / Networking"},
    {"pattern": r"virtualNetwork|vpc|subnet",                                                  "type": "Virtual Network"},
    {"pattern": r"user|servicePrincipal|managedIdentity|iam",                                  "type": "Identity"},
    {"pattern": r"diagnostic|monitor|insights|cloudwatch",                                     "type": "Observability"},
]


def _classify(asset_type: str, fallback_class: Optional[str] = None) -> Dict[str, str]:
    """Best-effort classification for a single asset_type string."""
    at = asset_type or ""
    sub = next(
        (r for r in SUBCATEGORY_RULES if re.search(r["pattern"], at, re.IGNORECASE)),
        None,
    )
    typ = next(
        (r for r in TYPE_RULES if re.search(r["pattern"], at, re.IGNORECASE)),
        None,
    )
    cat = CATEGORY_MAP.get(fallback_class or "other", CATEGORY_MAP["other"])
    return {
        "category": cat["name"],
        "category_icon": cat["icon"],
        "category_color": cat["color"],
        "subcategory": (sub["name"] if sub else "General"),
        "subcategory_icon": (sub["icon"] if sub else "Apps"),
        "type": (typ["type"] if typ else "Cloud Platform Service"),
    }


def _seeded_random_int(seed: str, min_v: int, max_v: int) -> int:
    """Stable mock value per technology so the UI doesn't flicker between renders."""
    h = int(hashlib.md5(seed.encode()).hexdigest()[:8], 16)
    return min_v + (h % (max_v - min_v + 1))


def _risk_level_for(asset_type: str, open_findings: int) -> str:
    if open_findings >= 5:
        return "critical"
    if open_findings >= 2:
        return "high"
    if open_findings >= 1:
        return "medium"
    return "low"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/")
async def get_technology_inventory(
    client_id: str,
    project_id: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    type_: Optional[str] = Query(None, alias="type"),
    status_filter: Optional[str] = Query(None, alias="status"),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """One-shot payload: summary, breakdowns by category/subcategory/type, and the
    full technology rows. Filterable so the SPA can re-fetch when a user picks a
    chip, but small enough that a single page load is fine."""
    try:
        return _build_technology_payload(db, client_id, project_id, category, type_, status_filter, search)
    except HTTPException:
        raise
    except Exception as exc:
        import logging
        logging.getLogger(__name__).exception("technology inventory failed")
        raise HTTPException(status_code=500, detail=f"technology inventory failed: {type(exc).__name__}: {exc}")


def _build_technology_payload(
    db: Session,
    client_id: str,
    project_id: Optional[str],
    category_filter: Optional[str],
    type_filter: Optional[str],
    status_filter: Optional[str],
    search: Optional[str],
) -> Dict[str, Any]:
    if not db.query(Client).filter(Client.id == client_id).first():
        raise HTTPException(status_code=404, detail="Client not found")

    asset_q = db.query(Asset).filter(
        Asset.client_id == client_id, Asset.status == AssetStatus.ACTIVE.value,
    )
    if project_id:
        asset_q = asset_q.filter(Asset.project_id == project_id)
    assets = asset_q.all()

    # Group: asset_type → list of assets
    by_type: Dict[str, List[Asset]] = defaultdict(list)
    for a in assets:
        if a.asset_type:
            by_type[a.asset_type].append(a)

    # Open findings per asset_type via Finding.resource_type / resource_id
    finding_counts: Dict[str, int] = defaultdict(int)
    fr_rows = (
        db.query(Finding.resource_type, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open")
        .group_by(Finding.resource_type)
        .all()
    )
    for rt, cnt in fr_rows:
        finding_counts[rt or ""] = int(cnt)

    # Build technology rows
    technologies: List[Dict[str, Any]] = []
    cat_counts: Dict[str, Dict[str, Any]] = {}
    sub_counts: Dict[str, Dict[str, Any]] = {}
    type_counts: Dict[str, int] = defaultdict(int)
    status_counter = {"healthy": 0, "warning": 0, "critical": 0, "ignored": 0}

    for at, items in by_type.items():
        # Use the most common asset_class among instances
        classes = [i.asset_class for i in items if i.asset_class]
        cls = max(set(classes), key=classes.count) if classes else "other"
        meta = _classify(at, cls)
        open_f = finding_counts.get(at, 0)
        risk = _risk_level_for(at, open_f)
        # status = healthy / warning / critical / ignored
        if any(i.status == "stale" or i.status == "deleted" for i in items[:5]):
            status_v = "ignored"
        elif risk == "critical":
            status_v = "critical"
        elif risk in ("high", "medium"):
            status_v = "warning"
        else:
            status_v = "healthy"

        last_seen = max((i.last_synced_at or datetime(1970, 1, 1, tzinfo=timezone.utc)) for i in items)
        environments = sorted({(i.tags or {}).get("env") or (i.tags or {}).get("environment") or "production" for i in items})

        # Mock-augmented fields (kept stable per technology via seeded hash)
        org_usage_pct = _seeded_random_int(f"usage:{at}", 5, 100)
        versions_detected = _seeded_random_int(f"ver:{at}", 1, 5)
        cve_count = _seeded_random_int(f"cve:{at}", 0, 12) if status_v != "healthy" else 0
        owner = ["platform-team", "security-team", "data-team", "iam-team"][_seeded_random_int(f"own:{at}", 0, 3)]

        row = {
            "id": at,
            "name": at,
            "resources_count": len(items),
            "type": meta["type"],
            "category": meta["category"],
            "category_icon": meta["category_icon"],
            "category_color": meta["category_color"],
            "subcategory": meta["subcategory"],
            "subcategory_icon": meta["subcategory_icon"],
            "organization_usage_pct": org_usage_pct,
            "status": status_v,
            "risk_level": risk,
            "open_findings": open_f,
            "cve_count": cve_count,
            "versions_detected": versions_detected,
            "owner": owner,
            "environments": environments,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "regions": sorted({i.region for i in items if i.region}),
            "subscriptions": sorted({i.subscription_id for i in items if i.subscription_id}),
        }

        # Apply filters
        if category_filter and row["category"] != category_filter:
            continue
        if type_filter and row["type"] != type_filter:
            continue
        if status_filter and row["status"] != status_filter:
            continue
        if search and search.lower() not in row["name"].lower() and search.lower() not in row["category"].lower():
            continue

        technologies.append(row)
        status_counter[status_v] = status_counter.get(status_v, 0) + 1
        # Aggregate breakdowns from filtered set
        c = cat_counts.setdefault(meta["category"], {"name": meta["category"], "icon": meta["category_icon"], "color": meta["category_color"], "count": 0})
        c["count"] += 1
        s = sub_counts.setdefault(meta["subcategory"], {"name": meta["subcategory"], "icon": meta["subcategory_icon"], "count": 0})
        s["count"] += 1
        type_counts[meta["type"]] += 1

    # Filter options (computed from unfiltered set so the dropdowns stay stable)
    all_categories = set()
    all_types = set()
    all_environments = set()
    all_regions = set()
    all_subscriptions = set()
    for at, items in by_type.items():
        classes = [i.asset_class for i in items if i.asset_class]
        cls = max(set(classes), key=classes.count) if classes else "other"
        m = _classify(at, cls)
        all_categories.add(m["category"])
        all_types.add(m["type"])
        for i in items:
            if i.region:
                all_regions.add(i.region)
            if i.subscription_id:
                all_subscriptions.add(i.subscription_id)
            envs = (i.tags or {}).get("env") or (i.tags or {}).get("environment")
            if envs:
                all_environments.add(envs)
    if not all_environments:
        all_environments = {"production", "staging", "development"}

    return {
        "summary": {
            "total": len(technologies),
            "by_status": status_counter,
        },
        "categories": sorted(cat_counts.values(), key=lambda x: -x["count"]),
        "subcategories": sorted(sub_counts.values(), key=lambda x: -x["count"]),
        "types": sorted(
            [{"name": k, "count": v} for k, v in type_counts.items()],
            key=lambda x: -x["count"],
        ),
        "technologies": sorted(technologies, key=lambda x: -x["resources_count"]),
        "filter_options": {
            "categories": sorted(all_categories),
            "types": sorted(all_types),
            "environments": sorted(all_environments),
            "regions": sorted(all_regions),
            "subscriptions": sorted(all_subscriptions),
            "owners": ["platform-team", "security-team", "data-team", "iam-team"],
            "statuses": ["healthy", "warning", "critical", "ignored"],
            "cloud_providers": ["azure", "aws", "gcp"],
        },
        "as_of": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{technology_name:path}/detail")
async def get_technology_detail(
    client_id: str,
    technology_name: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Detail drawer payload for a single technology (asset_type)."""
    items = db.query(Asset).filter(
        Asset.client_id == client_id, Asset.asset_type == technology_name,
        Asset.status == AssetStatus.ACTIVE.value,
    ).all()
    # Stale/deleted assets of this technology are listed SEPARATELY (not mixed
    # into the active counts) so they don't inflate the footprint.
    stale_items = db.query(Asset).filter(
        Asset.client_id == client_id, Asset.asset_type == technology_name,
        Asset.status.in_([AssetStatus.STALE.value, AssetStatus.DELETED.value]),
    ).all()
    if not items and not stale_items:
        raise HTTPException(status_code=404, detail="Technology not found in this client's inventory")

    classes = [i.asset_class for i in items if i.asset_class]
    cls = max(set(classes), key=classes.count) if classes else "other"
    meta = _classify(technology_name, cls)

    # Findings linked to any asset of this technology
    related = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.resource_type == technology_name)
        .order_by(desc(Finding.created_at))
        .limit(50)
        .all()
    )

    return {
        "name": technology_name,
        "category": meta["category"],
        "subcategory": meta["subcategory"],
        "type": meta["type"],
        "resources_count": len(items),
        "versions_detected": [
            {"version": f"v{_seeded_random_int(technology_name + str(i), 1, 9)}.{_seeded_random_int(technology_name + str(i) + 'm', 0, 9)}",
             "asset_count": _seeded_random_int(technology_name + str(i) + "c", 1, max(1, len(items) // 2))}
            for i in range(min(_seeded_random_int(technology_name, 1, 4), 4))
        ],
        "regions": sorted({i.region for i in items if i.region}),
        "subscriptions": sorted({i.subscription_id for i in items if i.subscription_id}),
        "open_findings": [
            {
                "id": f.id, "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "status": f.status, "resource_id": f.resource_id, "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
            }
            for f in related if f.status == "open"
        ],
        "assets": [
            {"id": a.id, "name": a.name, "external_id": a.external_id, "region": a.region,
             "subscription_id": a.subscription_id, "resource_group": a.resource_group,
             "status": a.status.value if hasattr(a.status, "value") else str(a.status)}
            for a in items[:100]
        ],
        # Listed separately in the UI — kept out of the active footprint.
        "stale_count": len(stale_items),
        "stale_assets": [
            {"id": a.id, "name": a.name, "external_id": a.external_id, "region": a.region,
             "subscription_id": a.subscription_id, "resource_group": a.resource_group,
             "status": a.status.value if hasattr(a.status, "value") else str(a.status)}
            for a in stale_items[:100]
        ],
        "owner": ["platform-team", "security-team", "data-team", "iam-team"][_seeded_random_int(f"own:{technology_name}", 0, 3)],
        "exposure_level": ["internal", "limited", "public"][_seeded_random_int(f"exp:{technology_name}", 0, 2)],
        "policies": [
            {"name": "Require encryption at rest",   "framework": "cis_azure", "control_id": "3.11", "status": "passing"},
            {"name": "Restrict public network access", "framework": "cis_azure", "control_id": "6.4", "status": "failing"},
        ][:_seeded_random_int(f"pol:{technology_name}", 0, 2)],
    }
