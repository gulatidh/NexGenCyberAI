"""Asset inventory sync — pull resources from a connector and persist to the assets table."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from api.models.models import Asset, AssetPlatformDetail, AssetStatus, Connector, ConnectorType
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


# ── Platform metadata extractors ──────────────────────────────────────────────
# Each returns (universal_fields, platform_metadata). universal_fields keys
# map to AssetPlatformDetail columns. platform_metadata is the full native schema.

def _detail_azure(resource: dict) -> Tuple[dict, dict]:
    rid = resource.get("id", "")
    props = resource.get("properties") or {}
    hw   = props.get("hardwareProfile") or {}
    os_  = (props.get("storageProfile") or {}).get("osDisk") or {}
    tags = resource.get("tags") or {}
    rg = sub = ""
    m = _AZURE_ARM_RE.match(rid)
    if m:
        sub = m.group("sub") or ""
        rg  = m.group("rg")  or ""
    ips = []
    if props.get("privateIPAddress"): ips.append(props["privateIPAddress"])
    if props.get("publicIPAddress"):  ips.append(props["publicIPAddress"])
    universal = {
        "tenant_account_id": sub or None,
        "namespace":         rg or None,
        "lifecycle_state":   (props.get("powerState") or props.get("provisioningState") or "").lower() or None,
        "owner":             tags.get("owner") or tags.get("Owner"),
        "department":        tags.get("department") or tags.get("Department"),
        "ip_addresses":      json.dumps(ips) if ips else None,
        "fqdn":              (props.get("dnsSettings") or {}).get("fqdn") or resource.get("fqdn"),
        "security_score":    None,
        "vulnerability_count": None,
    }
    metadata = {
        "subscription_id": sub, "resource_group": rg,
        "resource_type": resource.get("type", ""), "location": resource.get("location"),
        "sku": resource.get("sku"), "vm_size": hw.get("vmSize"),
        "os_type": os_.get("osType"), "power_state": props.get("powerState"),
        "provisioning_state": props.get("provisioningState"),
        "managed_identity": resource.get("identity"), "zones": resource.get("zones"),
        "private_ip": props.get("privateIPAddress"), "public_ip": props.get("publicIPAddress"),
        "arm_properties": props, "tags": tags,
    }
    return universal, metadata


def _detail_aws(resource: dict) -> Tuple[dict, dict]:
    rid  = resource.get("id", "")
    tags = resource.get("tags") or {}
    acc = reg = ""
    if rid.startswith("arn:"):
        parts = rid.split(":")
        if len(parts) >= 6:
            reg = parts[3] or ""
            acc = parts[4] or ""
    reg = reg or resource.get("region", "")
    tag_owner = tags.get("owner") or tags.get("Owner")
    tag_dept  = tags.get("department") or tags.get("Department") or tags.get("BusinessUnit")
    ips: List[str] = []
    for k in ("private_ip", "public_ip", "privateIpAddress", "publicIpAddress"):
        v = resource.get(k)
        if v and v not in ips: ips.append(v)
    state = resource.get("state") or {}
    state_name = state.get("Name") if isinstance(state, dict) else str(state or "")
    universal = {
        "tenant_account_id": acc or None,
        "namespace":         resource.get("vpc_id") or resource.get("VpcId"),
        "lifecycle_state":   (state_name or "").lower() or None,
        "owner":             tag_owner,
        "department":        tag_dept,
        "ip_addresses":      json.dumps(ips) if ips else None,
        "fqdn":              resource.get("public_dns") or resource.get("PublicDnsName") or resource.get("privateDnsName"),
        "security_score":    None,
        "vulnerability_count": None,
    }
    placement = resource.get("Placement") or {}
    metadata = {
        "account_id": acc, "region": reg,
        "vpc_id": resource.get("vpc_id") or resource.get("VpcId"),
        "subnet_id": resource.get("SubnetId"),
        "availability_zone": placement.get("AvailabilityZone") if isinstance(placement, dict) else None,
        "instance_type": resource.get("InstanceType"), "ami_id": resource.get("ImageId"),
        "security_group_ids": [sg.get("GroupId") for sg in (resource.get("SecurityGroups") or []) if isinstance(sg, dict)],
        "iam_profile": ((resource.get("IamInstanceProfile") or {}).get("Arn") if isinstance(resource.get("IamInstanceProfile"), dict) else None),
        "key_name": resource.get("KeyName"),
        "private_ip": resource.get("privateIpAddress") or resource.get("private_ip"),
        "public_ip": resource.get("publicIpAddress") or resource.get("public_ip"),
        "public_dns": resource.get("PublicDnsName") or resource.get("public_dns"),
        "state": state_name, "platform_details": resource.get("PlatformDetails") or resource.get("platform"),
        "launch_time": str(resource.get("LaunchTime") or resource.get("launch_time") or ""),
        "tags": tags,
    }
    return universal, metadata


def _detail_gcp(resource: dict) -> Tuple[dict, dict]:
    tags = resource.get("labels") or resource.get("tags") or {}
    proj = resource.get("project") or resource.get("project_id", "")
    nics = resource.get("networkInterfaces") or []
    ips: List[str] = []
    for nic in (nics if isinstance(nics, list) else []):
        if isinstance(nic, dict):
            if nic.get("networkIP"): ips.append(nic["networkIP"])
            for ac in (nic.get("accessConfigs") or []):
                if isinstance(ac, dict) and ac.get("natIP"): ips.append(ac["natIP"])
    universal = {
        "tenant_account_id": proj or None,
        "namespace":         resource.get("zone") or resource.get("location"),
        "lifecycle_state":   (resource.get("status") or "").lower() or None,
        "owner":             tags.get("owner"),
        "department":        tags.get("department"),
        "ip_addresses":      json.dumps(ips) if ips else None,
        "fqdn":              None,
        "security_score":    None,
        "vulnerability_count": None,
    }
    metadata = {
        "project_id": proj, "zone": resource.get("zone") or resource.get("location"),
        "machine_type": (resource.get("machineType") or "").rsplit("/", 1)[-1],
        "status": resource.get("status"),
        "network_tags": (resource.get("tags") or {}).get("items"),
        "network_interfaces": nics,
        "service_accounts": resource.get("serviceAccounts"),
        "disks": resource.get("disks"),
        "metadata_items": (resource.get("metadata") or {}).get("items"),
        "labels": tags,
    }
    return universal, metadata


def _detail_entraid(resource: dict) -> Tuple[dict, dict]:
    # New format from get_resources(): structured config dict per asset type.
    # Legacy format (raw Graph API) also handled via fallback.
    cfg      = resource.get("config") or {}
    profile  = resource.get("profile") or {}
    sign_in  = resource.get("signInActivity") or {}
    dept     = profile.get("department") or resource.get("department")
    rtype    = (resource.get("type") or "").lower()

    # Lifecycle state: for policy/singleton assets always active; for users use account_enabled
    if "user" in rtype:
        enabled = cfg.get("account_enabled") if cfg else resource.get("accountEnabled")
        lifecycle = "active" if enabled else "inactive"
        fqdn = cfg.get("mail") or resource.get("userPrincipalName")
    else:
        lifecycle = "active"
        fqdn = resource.get("name") or resource.get("displayName")

    universal = {
        "tenant_account_id": resource.get("tenantId"),
        "namespace":         dept or resource.get("type"),
        "lifecycle_state":   lifecycle,
        "owner":             None,
        "department":        dept,
        "ip_addresses":      None,
        "fqdn":              fqdn,
        "security_score":    None,
        "vulnerability_count": None,
    }
    # Store the full resource (including config dict) as platform_metadata so
    # the config-compliance engine can read config.* paths directly.
    metadata = {
        "object_id": resource.get("id"),
        "display_name": resource.get("name") or resource.get("displayName"),
        "resource_type": resource.get("type"),
        # Config block — all security-relevant properties collected by get_resources()
        "config": cfg,
        # Legacy fallbacks for old-format direct Graph API payloads
        "user_principal_name": resource.get("userPrincipalName"),
        "account_enabled": cfg.get("account_enabled") if cfg else resource.get("accountEnabled"),
        "user_type": cfg.get("user_type") if cfg else resource.get("userType"),
        "last_sign_in": cfg.get("last_sign_in") if cfg else sign_in.get("lastSignInDateTime"),
        "risk_level": cfg.get("risk_level") if cfg else resource.get("riskLevel"),
    }
    return universal, metadata


def _detail_okta(resource: dict) -> Tuple[dict, dict]:
    profile = resource.get("profile") or {}
    creds   = resource.get("credentials") or {}
    groups  = resource.get("groups") or []
    universal = {
        "tenant_account_id": resource.get("org_id") or resource.get("orgId"),
        "namespace":         profile.get("department") or (groups[0] if groups else None),
        "lifecycle_state":   (resource.get("status") or "").lower() or None,
        "owner":             profile.get("manager"),
        "department":        profile.get("department"),
        "ip_addresses":      None,
        "fqdn":              profile.get("login") or resource.get("login"),
        "security_score":    None,
        "vulnerability_count": None,
    }
    metadata = {
        "okta_id": resource.get("id"),
        "login": profile.get("login") or resource.get("login"),
        "email": profile.get("email"), "status": resource.get("status"),
        "first_name": profile.get("firstName"), "last_name": profile.get("lastName"),
        "job_title": profile.get("title"), "department": profile.get("department"),
        "manager": profile.get("manager"), "organization": profile.get("organization"),
        "groups": groups, "app_assignments": resource.get("apps"),
        "mfa_factors": resource.get("factors"),
        "last_login": resource.get("lastLogin"), "password_changed": resource.get("passwordChanged"),
        "created": resource.get("created"), "activated": resource.get("activated"),
        "provider": (creds.get("provider") or {}).get("name"),
    }
    return universal, metadata


def _detail_qualys(resource: dict) -> Tuple[dict, dict]:
    ips_raw = resource.get("ips") or resource.get("address") or []
    ips: List[str] = [ips_raw] if isinstance(ips_raw, str) else list(ips_raw) if isinstance(ips_raw, list) else []
    score = resource.get("score")
    vuln  = resource.get("vuln_count") or resource.get("open_vuln_count")
    universal = {
        "tenant_account_id": resource.get("customer_id") or resource.get("customerId"),
        "namespace":         resource.get("scanner_appliance") or resource.get("scannerAppliance"),
        "lifecycle_state":   "active",
        "owner":             resource.get("owner"),
        "department":        None,
        "ip_addresses":      json.dumps(ips) if ips else None,
        "fqdn":              resource.get("dns") or resource.get("fqdn") or resource.get("hostname"),
        "security_score":    float(score) if score is not None else None,
        "vulnerability_count": int(vuln) if vuln is not None else None,
    }
    metadata = {
        "qualys_id": resource.get("id") or resource.get("qualysId"),
        "tracking_method": resource.get("tracking_method") or resource.get("trackingMethod"),
        "scanner_appliance": resource.get("scanner_appliance") or resource.get("scannerAppliance"),
        "open_vulnerabilities": vuln,
        "last_scan_date": resource.get("last_scan_date") or resource.get("lastScanDate"),
        "os_cpe": resource.get("os_cpe") or resource.get("osCpe"),
        "open_ports": resource.get("open_ports") or resource.get("openPorts"),
        "software_installed": resource.get("software") or resource.get("softwareInstalled"),
        "ec2_instance_id": resource.get("ec2_instance_id"),
        "ips": ips, "dns": resource.get("dns") or resource.get("fqdn"),
        "netbios": resource.get("netbios"),
    }
    return universal, metadata


def _detail_servicenow(resource: dict) -> Tuple[dict, dict]:
    sys_domain = resource.get("sys_domain")
    tid = None
    if isinstance(sys_domain, dict):
        tid = sys_domain.get("value")
    else:
        tid = sys_domain or resource.get("instance_url")
    assigned_to = resource.get("assigned_to")
    owner = assigned_to.get("display_value") if isinstance(assigned_to, dict) else assigned_to
    dept = resource.get("department")
    dept_str = dept.get("display_value") if isinstance(dept, dict) else dept
    install_status_map = {"1": "active", "2": "on_order", "3": "maintenance",
                          "6": "in_maintenance", "7": "retired", "8": "stolen"}
    lifecycle = install_status_map.get(str(resource.get("install_status") or ""), "unknown")
    ip = resource.get("ip_address")
    universal = {
        "tenant_account_id": tid,
        "namespace":         resource.get("sys_class_name") or resource.get("cmdb_class"),
        "lifecycle_state":   lifecycle,
        "owner":             owner,
        "department":        dept_str,
        "ip_addresses":      json.dumps([ip]) if ip else None,
        "fqdn":              resource.get("fqdn") or resource.get("dns_domain") or resource.get("name"),
        "security_score":    None,
        "vulnerability_count": None,
    }
    metadata = {
        "sys_id": resource.get("sys_id"),
        "cmdb_class": resource.get("sys_class_name") or resource.get("cmdb_class"),
        "category": resource.get("category"), "subcategory": resource.get("subcategory"),
        "install_status": resource.get("install_status"), "environment": resource.get("environment"),
        "assigned_to": assigned_to, "managed_by": resource.get("managed_by"),
        "support_group": resource.get("support_group"),
        "business_service": resource.get("business_service"),
        "maintenance_schedule": resource.get("maintenance_schedule"),
        "change_control": resource.get("change_number"),
        "last_discovered": resource.get("last_discovered"),
        "ip_address": ip, "fqdn": resource.get("fqdn"),
        "os": resource.get("os"), "os_version": resource.get("os_version"),
        "serial_number": resource.get("serial_number"), "model_id": resource.get("model_id"),
    }
    return universal, metadata


def _detail_cyberark(resource: dict) -> Tuple[dict, dict]:
    addr = resource.get("address") or resource.get("Address")
    safe = resource.get("safe") or resource.get("Safe")
    universal = {
        "tenant_account_id": safe,
        "namespace":         resource.get("folder") or resource.get("Folder"),
        "lifecycle_state":   "active",
        "owner":             resource.get("username") or resource.get("UserName"),
        "department":        None,
        "ip_addresses":      json.dumps([addr]) if addr else None,
        "fqdn":              addr,
        "security_score":    None,
        "vulnerability_count": None,
    }
    metadata = {
        "account_id": resource.get("id") or resource.get("AccountID"),
        "safe": safe, "folder": resource.get("folder") or resource.get("Folder"),
        "username": resource.get("username") or resource.get("UserName"),
        "address": addr,
        "platform_id": resource.get("platformId") or resource.get("PlatformID"),
        "last_modified": resource.get("lastModifiedTime") or resource.get("LastModifiedTime"),
        "secret_management": resource.get("secretManagement"),
        "remote_machines": resource.get("remoteMachinesAccess"),
    }
    return universal, metadata


def _detail_onprem(resource: dict) -> Tuple[dict, dict]:
    ips_raw = resource.get("ip_addresses") or resource.get("ips") or []
    ips: List[str] = [ips_raw] if isinstance(ips_raw, str) else list(ips_raw)
    universal = {
        "tenant_account_id": resource.get("site_name") or resource.get("site"),
        "namespace":         resource.get("ou") or resource.get("domain"),
        "lifecycle_state":   "active" if resource.get("active", True) else "inactive",
        "owner":             resource.get("owner"),
        "department":        resource.get("department"),
        "ip_addresses":      json.dumps(ips) if ips else None,
        "fqdn":              resource.get("fqdn") or resource.get("hostname"),
        "security_score":    None,
        "vulnerability_count": None,
    }
    metadata = {
        "hostname": resource.get("hostname"), "os_type": resource.get("os_type"),
        "os_version": resource.get("os_version"), "ip_addresses": ips,
        "mac_addresses": resource.get("mac_addresses"),
        "cpu_count": resource.get("cpu_count"), "memory_gb": resource.get("memory_gb"),
        "disk_gb": resource.get("disk_gb"), "domain": resource.get("domain"),
        "agent_version": resource.get("agent_version"),
        "last_heartbeat": resource.get("last_heartbeat"),
        "installed_software": resource.get("software"),
    }
    return universal, metadata


def _detail_generic(resource: dict, connector_type_str: str) -> Tuple[dict, dict]:
    ips: List[str] = []
    for k in ("ip_address", "ip", "private_ip", "public_ip", "address"):
        v = resource.get(k)
        if v and isinstance(v, str) and v not in ips:
            ips.append(v)
    score = resource.get("score")
    vuln  = resource.get("vuln_count")
    universal = {
        "tenant_account_id": resource.get("account_id") or resource.get("tenant_id") or resource.get("org_id"),
        "namespace":         resource.get("namespace") or resource.get("group") or resource.get("category"),
        "lifecycle_state":   (str(resource.get("status") or resource.get("state") or "")).lower() or None,
        "owner":             resource.get("owner"),
        "department":        resource.get("department"),
        "ip_addresses":      json.dumps(ips) if ips else None,
        "fqdn":              resource.get("fqdn") or resource.get("hostname") or resource.get("dns"),
        "security_score":    float(score) if score is not None else None,
        "vulnerability_count": int(vuln) if vuln is not None else None,
    }
    metadata = dict(resource)  # full pass-through for unknown connectors
    return universal, metadata


def _extract_platform_detail(connector_type_str: str, resource: dict) -> Tuple[dict, dict]:
    ct = connector_type_str.lower()
    if ct == "azure":           return _detail_azure(resource)
    if ct == "aws":             return _detail_aws(resource)
    if ct == "gcp":             return _detail_gcp(resource)
    if ct in ("entraid", "entra_id", "entra"): return _detail_entraid(resource)
    if ct == "okta":            return _detail_okta(resource)
    if ct == "qualys":          return _detail_qualys(resource)
    if ct == "servicenow":      return _detail_servicenow(resource)
    if ct == "cyberark":        return _detail_cyberark(resource)
    if ct in ("onprem", "on_prem", "on-prem"): return _detail_onprem(resource)
    return _detail_generic(resource, ct)


def _upsert_platform_detail(db: Session, asset_id: str, connector_type: str, raw: dict, now: datetime) -> None:
    try:
        universal, platform_meta = _extract_platform_detail(connector_type, raw)
        detail = db.query(AssetPlatformDetail).filter(AssetPlatformDetail.asset_id == asset_id).first()
        if detail is None:
            kwargs = {k: v for k, v in universal.items() if v is not None}
            detail = AssetPlatformDetail(
                asset_id=asset_id,
                connector_type=connector_type,
                platform_metadata=json.dumps(platform_meta, default=str),
                synced_at=now,
                **kwargs,
            )
            db.add(detail)
        else:
            detail.connector_type = connector_type
            for k, v in universal.items():
                if v is not None:
                    setattr(detail, k, v)
            detail.platform_metadata = json.dumps(platform_meta, default=str)
            detail.synced_at = now
    except Exception as exc:
        logger.warning("Failed to upsert platform detail for asset %s: %s", asset_id, exc)


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
) -> Tuple[int, int, int]:
    """Pull resources from one connector and upsert them into the assets table.

    Found assets → ACTIVE (re-stamps reappeared_at if they were previously STALE).
    Not found → STALE (only when the API returned a non-empty result so a total
    API failure never wipes the inventory).

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
    created = updated = marked_stale = 0

    for raw in raw_resources or []:
        parsed = _parse_resource(connector_db.connector_type, raw)
        if not parsed:
            continue
        ext = parsed["external_id"]
        seen_ids.add(ext)
        existing_row = existing.get(ext)

        if existing_row is None:
            # Brand new resource — create as NEW (pending user approval)
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
                status=AssetStatus.NEW,
                first_seen_at=now,
                last_synced_at=now,
            )
            db.add(asset)
            ct_str = connector_db.connector_type.value if hasattr(connector_db.connector_type, "value") else str(connector_db.connector_type)
            _upsert_platform_detail(db, asset.id, ct_str, raw, now)
            created += 1
        else:
            current = existing_row.status
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
            existing_row.last_synced_at = now
            if current == AssetStatus.STALE:
                existing_row.status = AssetStatus.REAPPEARED
                existing_row.reappeared_at = now
            # ACTIVE, NEW, REAPPEARED → no status change
            ct_str = connector_db.connector_type.value if hasattr(connector_db.connector_type, "value") else str(connector_db.connector_type)
            _upsert_platform_detail(db, existing_row.id, ct_str, raw, now)
            updated += 1

    # Mark ACTIVE assets stale when API returned results (non-empty = auth working)
    if seen_ids:
        for ext, row in existing.items():
            if ext not in seen_ids and row.status == AssetStatus.ACTIVE:
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
