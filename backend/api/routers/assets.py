"""Asset Inventory endpoints — list assets, detail with related findings/risks, sync, on-demand scan."""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, distinct
from typing import List, Optional, Dict, Any

from api.models.models import (
    Asset, AssetStatus, Connector, Finding, Risk, Scan, ScanStatus, ScanType,
)
from api.schemas.schemas import (
    AssetResponse, AssetDetailResponse, AssetSyncResponse, ScanResponse,
)
from db.database import get_db
from core.security import get_current_user
from connectors.sync import sync_connector_assets_bg

router = APIRouter(prefix="/clients/{client_id}/assets", tags=["assets"])


# ── Helpers ────────────────────────────────────────────────────────────────────

def _findings_for_asset(db: Session, client_id: str, asset: Asset) -> List[Finding]:
    """Return all findings whose resource_id equals the asset's external_id (across all scans for the client)."""
    return (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.resource_id == asset.external_id,
        )
        .order_by(desc(Finding.created_at))
        .all()
    )


def _risks_for_findings(db: Session, client_id: str, finding_ids: List[str]) -> List[Risk]:
    """Risk.finding_ids is a JSON list. SQLite/MSSQL JSON-contains is non-portable, so filter in Python."""
    if not finding_ids:
        return []
    finding_id_set = set(finding_ids)
    all_risks = db.query(Risk).filter(Risk.client_id == client_id).all()
    matched: List[Risk] = []
    for r in all_risks:
        ids = r.finding_ids or []
        if any(fid in finding_id_set for fid in ids):
            matched.append(r)
    return matched


def _serialize_asset_row(
    db: Session, client_id: str, asset: Asset, finding_counts: Dict[str, int], risk_counts: Dict[str, int]
) -> Dict[str, Any]:
    return {
        "id": asset.id,
        "client_id": asset.client_id,
        "connector_id": asset.connector_id,
        "external_id": asset.external_id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "asset_class": asset.asset_class,
        "region": asset.region,
        "subscription_id": asset.subscription_id,
        "resource_group": asset.resource_group,
        "account_id": asset.account_id,
        "cloud_project_id": asset.cloud_project_id,
        "project_id": asset.project_id,
        "tags": asset.tags or {},
        "status": asset.status,
        "first_seen_at": asset.first_seen_at,
        "last_synced_at": asset.last_synced_at,
        "open_findings_count": finding_counts.get(asset.external_id, 0),
        "risks_count": risk_counts.get(asset.id, 0),
    }


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/", response_model=List[AssetResponse])
async def list_assets(
    client_id: str,
    connector_id: Optional[str] = None,
    project_id: Optional[str] = None,
    asset_class: Optional[str] = None,
    subscription_id: Optional[str] = None,
    resource_group: Optional[str] = None,
    region: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    query = db.query(Asset).filter(Asset.client_id == client_id)
    if connector_id:
        query = query.filter(Asset.connector_id == connector_id)
    if project_id:
        query = query.filter(Asset.project_id == project_id)
    if asset_class:
        query = query.filter(Asset.asset_class == asset_class)
    if subscription_id:
        query = query.filter(Asset.subscription_id == subscription_id)
    if resource_group:
        query = query.filter(Asset.resource_group == resource_group)
    if region:
        query = query.filter(Asset.region == region)
    # Inventory defaults to LIVE assets. Stale/deleted are kept for audit but
    # excluded from the main list (and from all analysis/assessments/reports);
    # the dedicated Stale Assets view requests them via status=archived.
    #   active (default) | stale | deleted | archived (stale+deleted) | all
    status_norm = (status or "active").lower()
    if status_norm == "all":
        pass
    elif status_norm == "archived":
        query = query.filter(Asset.status.in_([AssetStatus.STALE.value, AssetStatus.DELETED.value]))
    else:
        query = query.filter(Asset.status == status_norm)
    if q:
        query = query.filter(Asset.name.ilike(f"%{q}%"))
    assets = query.order_by(Asset.name.asc()).limit(500).all()

    # Compute open-findings counts grouped by resource_id (external_id) in one query.
    finding_count_rows = (
        db.query(Finding.resource_id, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open")
        .group_by(Finding.resource_id)
        .all()
    )
    finding_counts = {rid: cnt for rid, cnt in finding_count_rows if rid}

    # Risk counts: derive from finding_ids (Python-side join).
    finding_to_resource = dict(
        db.query(Finding.id, Finding.resource_id)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id)
        .all()
    )
    asset_resource_to_id = {a.external_id: a.id for a in assets}
    risk_counts: Dict[str, int] = {a.id: 0 for a in assets}
    for r in db.query(Risk).filter(Risk.client_id == client_id).all():
        seen_assets: set = set()
        for fid in (r.finding_ids or []):
            res_id = finding_to_resource.get(fid)
            if not res_id:
                continue
            asset_id = asset_resource_to_id.get(res_id)
            if asset_id and asset_id not in seen_assets:
                seen_assets.add(asset_id)
                risk_counts[asset_id] = risk_counts.get(asset_id, 0) + 1

    return [_serialize_asset_row(db, client_id, a, finding_counts, risk_counts) for a in assets]


@router.get("/facets")
async def get_facets(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    # Facets describe the LIVE inventory (the default list view), so exclude
    # stale/deleted to keep the filter counts honest.
    base = db.query(Asset).filter(
        Asset.client_id == client_id, Asset.status == AssetStatus.ACTIVE.value,
    )
    return {
        "asset_class": [r[0] for r in base.with_entities(distinct(Asset.asset_class)).all() if r[0]],
        "region": [r[0] for r in base.with_entities(distinct(Asset.region)).all() if r[0]],
        "subscription_id": [r[0] for r in base.with_entities(distinct(Asset.subscription_id)).all() if r[0]],
        "resource_group": [r[0] for r in base.with_entities(distinct(Asset.resource_group)).all() if r[0]],
        "account_id": [r[0] for r in base.with_entities(distinct(Asset.account_id)).all() if r[0]],
        "cloud_project_id": [r[0] for r in base.with_entities(distinct(Asset.cloud_project_id)).all() if r[0]],
        "project_id": [r[0] for r in base.with_entities(distinct(Asset.project_id)).all() if r[0]],
        "connector_id": [r[0] for r in base.with_entities(distinct(Asset.connector_id)).all() if r[0]],
    }


@router.get("/{asset_id}", response_model=AssetDetailResponse)
async def get_asset_detail(
    client_id: str,
    asset_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.client_id == client_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    findings = _findings_for_asset(db, client_id, asset)
    open_count = sum(1 for f in findings if f.status == "open")
    risks = _risks_for_findings(db, client_id, [f.id for f in findings])

    return {
        "id": asset.id,
        "client_id": asset.client_id,
        "connector_id": asset.connector_id,
        "external_id": asset.external_id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "asset_class": asset.asset_class,
        "region": asset.region,
        "subscription_id": asset.subscription_id,
        "resource_group": asset.resource_group,
        "account_id": asset.account_id,
        "cloud_project_id": asset.cloud_project_id,
        "project_id": asset.project_id,
        "tags": asset.tags or {},
        "status": asset.status,
        "first_seen_at": asset.first_seen_at,
        "last_synced_at": asset.last_synced_at,
        "open_findings_count": open_count,
        "risks_count": len(risks),
        "provider_metadata": asset.provider_metadata or {},
        "findings": findings,
        "risks": risks,
    }


@router.post("/sync/", response_model=AssetSyncResponse, status_code=202)
async def sync_assets(
    client_id: str,
    background_tasks: BackgroundTasks,
    connector_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(Connector).filter(Connector.client_id == client_id)
    if connector_id:
        q = q.filter(Connector.id == connector_id)
    connectors_db = q.all()
    if not connectors_db:
        raise HTTPException(status_code=404, detail="No connector found for sync")

    queued: List[str] = []
    for c in connectors_db:
        background_tasks.add_task(sync_connector_assets_bg, c.id)
        queued.append(c.id)

    return {
        "queued_connector_ids": queued,
        "message": f"Queued asset sync for {len(queued)} connector(s)",
    }


@router.post("/restore-stale/")
async def restore_stale_assets(
    client_id: str,
    connector_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Mark all STALE assets as ACTIVE again.

    Use this to recover assets that were incorrectly demoted to STALE — e.g. after
    a scan-triggered sync that had an incomplete API response.  A full explicit Sync
    will re-evaluate and re-apply STALE to assets truly absent from the live inventory.
    """
    q = db.query(Asset).filter(
        Asset.client_id == client_id,
        Asset.status == AssetStatus.STALE,
    )
    if connector_id:
        q = q.filter(Asset.connector_id == connector_id)
    stale = q.all()
    for a in stale:
        a.status = AssetStatus.ACTIVE
    db.commit()
    return {"restored": len(stale)}


@router.post("/{asset_id}/scan/", response_model=ScanResponse, status_code=201)
async def scan_asset(
    client_id: str,
    asset_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Trigger an on-demand scan scoped to a single asset.

    Runs the connector's full configuration + vulnerability scan, then post-filters
    persisted findings to only those whose resource_id matches this asset's external_id.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.client_id == client_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    scan = Scan(
        client_id=client_id,
        connector_id=asset.connector_id,
        scan_type=ScanType.FULL,
        initiated_by=user.get("upn", user.get("preferred_username", "system")),
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from api.routers.scans import _execute_scan
    from core.config import get_settings
    background_tasks.add_task(
        _execute_scan, scan.id, get_settings().DATABASE_URL, asset.external_id
    )
    return scan
