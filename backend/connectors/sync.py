"""Asset inventory sync — pull resources from a connector and persist to the assets table."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from api.models.models import Asset, AssetStatus, Connector, ConnectorType
from connectors.factory import get_connector
from core.encryption import decrypt

logger = logging.getLogger(__name__)


_AZURE_ARM_RE = re.compile(
    r"^/subscriptions/(?P<sub>[^/]+)/resourceGroups/(?P<rg>[^/]+)"
    r"(?:/providers/(?P<provider>[^/]+)/(?P<rtype>[^/]+))?",
    re.IGNORECASE,
)

_AZURE_TYPE_TO_CLASS = {
    "microsoft.compute": "vm",
    "microsoft.storage": "storage",
    "microsoft.network": "network",
    "microsoft.sql": "database",
    "microsoft.dbforpostgresql": "database",
    "microsoft.dbformysql": "database",
    "microsoft.documentdb": "database",
    "microsoft.keyvault": "keyvault",
    "microsoft.web": "vm",
    "microsoft.containerservice": "vm",
    "microsoft.containerregistry": "storage",
}

_AWS_SERVICE_TO_CLASS = {
    "ec2": "vm",
    "s3": "storage",
    "rds": "database",
    "dynamodb": "database",
    "iam": "identity",
    "kms": "keyvault",
    "secretsmanager": "keyvault",
    "lambda": "vm",
    "ecs": "vm",
    "eks": "vm",
}

_GCP_SERVICE_TO_CLASS = {
    "compute.googleapis.com": "vm",
    "storage.googleapis.com": "storage",
    "sqladmin.googleapis.com": "database",
    "bigquery.googleapis.com": "database",
    "iam.googleapis.com": "identity",
    "cloudkms.googleapis.com": "keyvault",
}


def _parse_azure(resource: Dict[str, Any]) -> Dict[str, Any]:
    rid: str = resource.get("id") or ""
    parsed = {"external_id": rid, "name": resource.get("name") or rid.rsplit("/", 1)[-1]}
    m = _AZURE_ARM_RE.match(rid)
    if m:
        parsed["subscription_id"] = m.group("sub")
        parsed["resource_group"] = m.group("rg")
    rtype: str = resource.get("type") or ""
    parsed["asset_type"] = rtype
    provider = rtype.split("/", 1)[0].lower() if rtype else ""
    parsed["asset_class"] = _AZURE_TYPE_TO_CLASS.get(provider, "other")
    parsed["region"] = resource.get("location")
    parsed["tags"] = resource.get("tags") or {}
    return parsed


def _parse_aws(resource: Dict[str, Any]) -> Dict[str, Any]:
    rid: str = resource.get("id") or ""
    parsed = {"external_id": rid, "name": resource.get("name") or rid}
    rtype = resource.get("type") or ""
    parsed["asset_type"] = rtype
    if rid.startswith("arn:"):
        parts = rid.split(":")
        if len(parts) >= 6:
            parsed["region"] = parts[3] or None
            parsed["account_id"] = parts[4] or None
            service = parts[2]
            parsed["asset_class"] = _AWS_SERVICE_TO_CLASS.get(service, "other")
    else:
        # E.g. raw EC2 id "i-..." — derive class from supplied type field
        rtype_lower = rtype.lower()
        if "ec2" in rtype_lower:
            parsed["asset_class"] = "vm"
        elif "s3" in rtype_lower or "bucket" in rtype_lower:
            parsed["asset_class"] = "storage"
        else:
            parsed["asset_class"] = "other"
        parsed["region"] = resource.get("region")
    parsed["tags"] = resource.get("tags") or {}
    return parsed


def _parse_gcp(resource: Dict[str, Any]) -> Dict[str, Any]:
    rid: str = resource.get("id") or ""
    parsed = {"external_id": rid, "name": resource.get("name") or rid.rsplit("/", 1)[-1]}
    rtype = resource.get("type") or ""
    parsed["asset_type"] = rtype
    parsed["project_id"] = resource.get("project") or resource.get("project_id")
    if not parsed["project_id"]:
        m = re.search(r"/projects/([^/]+)/", rid)
        if m:
            parsed["project_id"] = m.group(1)
    service = rtype.split("/", 1)[0] if "/" in rtype else rtype
    parsed["asset_class"] = _GCP_SERVICE_TO_CLASS.get(service, "other")
    parsed["region"] = resource.get("location") or resource.get("region")
    parsed["tags"] = resource.get("labels") or resource.get("tags") or {}
    return parsed


def _parse_entraid(resource: Dict[str, Any]) -> Dict[str, Any]:
    rid: str = resource.get("id") or ""
    return {
        "external_id": rid,
        "name": resource.get("displayName") or resource.get("userPrincipalName") or rid,
        "asset_type": resource.get("type") or "entraid/user",
        "asset_class": "identity",
        "region": None,
        "tags": {},
    }


def _parse_generic(resource: Dict[str, Any]) -> Dict[str, Any]:
    rid = resource.get("id") or resource.get("name") or ""
    return {
        "external_id": str(rid),
        "name": resource.get("name") or str(rid),
        "asset_type": resource.get("type") or "",
        "asset_class": "other",
        "region": resource.get("region") or resource.get("location"),
        "tags": resource.get("tags") or {},
    }


def _parse_resource(connector_type: ConnectorType, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not resource:
        return None
    try:
        ct = connector_type.value if hasattr(connector_type, "value") else str(connector_type)
        if ct == "azure":
            parsed = _parse_azure(resource)
        elif ct == "aws":
            parsed = _parse_aws(resource)
        elif ct == "gcp":
            parsed = _parse_gcp(resource)
        elif ct == "entraid":
            parsed = _parse_entraid(resource)
        else:
            parsed = _parse_generic(resource)
        if not parsed.get("external_id"):
            return None
        return parsed
    except Exception as exc:
        logger.warning("Failed to parse resource %s: %s", resource, exc)
        return None


async def sync_connector_assets(
    db: Session,
    connector_db: Connector,
    mark_stale: bool = False,
) -> Tuple[int, int, int]:
    """Pull resources from one connector and upsert them into the assets table.

    By default (mark_stale=False) this function only ADDS new assets and UPDATES
    existing ones.  It never demotes ACTIVE assets to STALE automatically.
    Cloud APIs are unreliable — a single incomplete API response should not cause
    assets to silently disappear from the inventory.

    Pass mark_stale=True only when the caller has explicitly verified a full,
    complete API response and wants to reconcile the inventory (e.g. a dedicated
    "Audit inventory" action triggered by the user).

    Returns (created, updated, marked_stale).
    """
    if not connector_db.credentials_enc:
        logger.info("Connector %s has no credentials; skipping asset sync", connector_db.id)
        return (0, 0, 0)

    creds = json.loads(decrypt(connector_db.credentials_enc))
    runtime = get_connector(connector_db.connector_type, creds, connector_db.config or {})

    raw_resources: List[Dict[str, Any]] = await runtime.get_resources()
    now = datetime.now(timezone.utc)

    existing = {a.external_id: a for a in db.query(Asset).filter(Asset.connector_id == connector_db.id).all()}
    seen_ids: set = set()
    created = updated = 0

    for raw in raw_resources or []:
        parsed = _parse_resource(connector_db.connector_type, raw)
        if not parsed:
            continue
        ext = parsed["external_id"]
        seen_ids.add(ext)
        existing_row = existing.get(ext)
        if existing_row is None:
            asset = Asset(
                client_id=connector_db.client_id,
                project_id=connector_db.project_id,
                connector_id=connector_db.id,
                external_id=ext,
                name=parsed.get("name") or ext,
                asset_type=parsed.get("asset_type"),
                asset_class=parsed.get("asset_class"),
                region=parsed.get("region"),
                subscription_id=parsed.get("subscription_id"),
                resource_group=parsed.get("resource_group"),
                account_id=parsed.get("account_id"),
                cloud_project_id=parsed.get("project_id"),
                tags=parsed.get("tags") or {},
                provider_metadata=raw,
                status=AssetStatus.ACTIVE,
                first_seen_at=now,
                last_synced_at=now,
            )
            db.add(asset)
            created += 1
        else:
            was_stale = existing_row.status == AssetStatus.STALE
            existing_row.name = parsed.get("name") or existing_row.name
            existing_row.asset_type = parsed.get("asset_type") or existing_row.asset_type
            existing_row.asset_class = parsed.get("asset_class") or existing_row.asset_class
            existing_row.region = parsed.get("region") or existing_row.region
            existing_row.subscription_id = parsed.get("subscription_id") or existing_row.subscription_id
            existing_row.resource_group = parsed.get("resource_group") or existing_row.resource_group
            existing_row.account_id = parsed.get("account_id") or existing_row.account_id
            existing_row.cloud_project_id = parsed.get("project_id") or existing_row.cloud_project_id
            existing_row.tags = parsed.get("tags") or {}
            existing_row.provider_metadata = raw
            existing_row.status = AssetStatus.ACTIVE
            existing_row.last_synced_at = now
            if was_stale:
                existing_row.reappeared_at = now  # "R" badge on the frontend
            updated += 1

    # Stamp last_synced_at on ALL assets for this connector so the Assets page
    # always shows a fresh "last synced" time — even for assets the API didn't
    # return this round (e.g. beyond a pagination cap or temporarily missing).
    for row in existing.values():
        row.last_synced_at = now

    marked_stale = 0
    if mark_stale:
        for ext, row in existing.items():
            if ext not in seen_ids and row.status != AssetStatus.STALE:
                row.status = AssetStatus.STALE
                marked_stale += 1

    connector_db.last_synced_at = now
    db.commit()
    logger.info(
        "Asset sync for connector %s (%s): created=%d updated=%d stale=%d",
        connector_db.id, connector_db.connector_type, created, updated, marked_stale,
    )
    return (created, updated, marked_stale)


async def sync_connector_assets_bg(connector_id: str) -> None:
    """Background-task entry point: open its own session, run sync, close."""
    from db.database import SessionLocal

    db = SessionLocal()
    try:
        connector_db = db.query(Connector).filter(Connector.id == connector_id).first()
        if not connector_db:
            logger.warning("Asset sync requested for missing connector %s", connector_id)
            return
        try:
            await sync_connector_assets(db, connector_db)
        except Exception as exc:
            logger.exception("Asset sync failed for connector %s: %s", connector_id, exc)
            db.rollback()
    finally:
        db.close()
