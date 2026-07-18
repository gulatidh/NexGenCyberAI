"""
NexGenCyberAI - Azure Connector
Direct ARM API scanning (NSG, storage, VMs, Key Vault, RBAC, Monitor)
enriched by Defender for Cloud when available.
"""
import logging
from typing import Any, Dict, List

from azure.identity import ClientSecretCredential, ManagedIdentityCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.monitor import MonitorManagementClient

from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity
from connectors.azure.control_mappings import (
    defender_mappings, mappings_for, nsg_port_mappings,
)

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "High": FindingSeverity.HIGH,
    "Medium": FindingSeverity.MEDIUM,
    "Low": FindingSeverity.LOW,
}

NIST_CONTROL_MAP = {
    "MFA should be enabled on accounts with owner permissions": "NIST AC-2",
    "Secure transfer to storage accounts should be enabled": "NIST SC-8",
    "Network security groups should be applied on subnets": "NIST SC-7",
    "Just-In-Time network access control should be applied on virtual machines": "NIST AC-17",
    "Endpoint protection should be installed on machines": "NIST SI-3",
}

# Port → (service name, NIST control, severity)
RISKY_PORTS: Dict[int, tuple] = {
    22:   ("SSH",        "NIST AC-17", FindingSeverity.HIGH),
    3389: ("RDP",        "NIST AC-17", FindingSeverity.CRITICAL),
    23:   ("Telnet",     "NIST SC-8",  FindingSeverity.CRITICAL),
    21:   ("FTP",        "NIST SC-8",  FindingSeverity.HIGH),
    5900: ("VNC",        "NIST AC-17", FindingSeverity.HIGH),
    1433: ("MSSQL",      "NIST SC-7",  FindingSeverity.HIGH),
    3306: ("MySQL",      "NIST SC-7",  FindingSeverity.HIGH),
    5432: ("PostgreSQL", "NIST SC-7",  FindingSeverity.HIGH),
    6379: ("Redis",      "NIST SC-7",  FindingSeverity.HIGH),
    27017:("MongoDB",    "NIST SC-7",  FindingSeverity.HIGH),
    9200: ("Elasticsearch", "NIST SC-7", FindingSeverity.HIGH),
}

# Built-in role definition GUIDs (subscription scope)
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_ROLE_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c"

# Known endpoint-protection VM extension types
EP_EXTENSION_TYPES = {
    "IaaSAntimalware", "EndpointSecurity", "TrendMicroDSA",
    "MDE.Linux", "MDE.Windows",
    "MicrosoftMonitoringAgent", "OmsAgentForLinux",
    "AzureSecurityWindowsAgent", "AzureSecurityLinuxAgent",
}


class AzureConnector(BaseConnector):

    def _build_credential(self):
        if self.credentials.get("use_managed_identity"):
            return ManagedIdentityCredential()
        return ClientSecretCredential(
            tenant_id=self.credentials["tenant_id"],
            client_id=self.credentials["client_id"],
            client_secret=self.credentials["client_secret"],
        )

    # ── Connection test ───────────────────────────────────────────────────────

    async def test_connection(self) -> ConnectorTestResult:
        try:
            cred = self._build_credential()
            subscription_id = self.credentials["subscription_id"]
            client = ResourceManagementClient(cred, subscription_id)
            rgs = list(client.resource_groups.list())
            return ConnectorTestResult(
                success=True,
                message=f"Connected. Found {len(rgs)} resource groups.",
                details={"resource_groups": len(rgs)},
            )
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    # ── Resource inventory ────────────────────────────────────────────────────

    async def get_resources(self) -> List[Dict[str, Any]]:
        cred = self._build_credential()
        sub_id = self.credentials["subscription_id"]
        resources = []

        # Storage accounts
        try:
            from azure.mgmt.storage import StorageManagementClient
            sc = StorageManagementClient(cred, sub_id)
            for sa in sc.storage_accounts.list():
                resources.append({
                    "id": sa.id or "", "name": sa.name or "",
                    "type": "Microsoft.Storage/storageAccounts",
                    "location": sa.location or "",
                    "config": {
                        "https_only": getattr(sa, "enable_https_traffic_only", None),
                        "min_tls_version": str(getattr(sa, "minimum_tls_version", "") or ""),
                        "allow_blob_public_access": getattr(sa, "allow_blob_public_access", None),
                        "network_acls_default_action": str(getattr(getattr(sa, "network_rule_set", None), "default_action", "") or ""),
                        "encryption_enabled": bool(getattr(sa, "encryption", None)),
                    },
                })
        except Exception as exc:
            logger.debug("Azure get_resources storage failed: %s", exc)

        # Key Vaults
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            kvc = KeyVaultManagementClient(cred, sub_id)
            for kv in kvc.vaults.list():
                props = getattr(kv, "properties", None)
                resources.append({
                    "id": kv.id or "", "name": kv.name or "",
                    "type": "Microsoft.KeyVault/vaults",
                    "location": kv.location or "",
                    "config": {
                        "soft_delete_enabled": getattr(props, "enable_soft_delete", None) if props else None,
                        "purge_protection_enabled": getattr(props, "enable_purge_protection", None) if props else None,
                        "public_network_access": str(getattr(props, "public_network_access", "") or "") if props else "",
                        "sku": str(getattr(getattr(props, "sku", None), "name", "") or "") if props else "",
                    },
                })
        except Exception as exc:
            logger.debug("Azure get_resources keyvault failed: %s", exc)

        # Virtual Machines
        try:
            from azure.mgmt.compute import ComputeManagementClient
            cc = ComputeManagementClient(cred, sub_id)
            for vm in cc.virtual_machines.list_all():
                sp = getattr(vm, "storage_profile", None)
                os_disk = getattr(sp, "os_disk", None) if sp else None
                enc = getattr(os_disk, "encryption_settings", None) if os_disk else None
                os_profile = getattr(vm, "os_profile", None)
                resources.append({
                    "id": vm.id or "", "name": vm.name or "",
                    "type": "Microsoft.Compute/virtualMachines",
                    "location": vm.location or "",
                    "config": {
                        "disk_encryption_enabled": bool(enc and getattr(enc, "enabled", False)),
                        "os_disk_type": str(getattr(os_disk, "os_type", "") or "") if os_disk else "",
                        "admin_username": getattr(os_profile, "admin_username", None) if os_profile else None,
                    },
                })
        except Exception as exc:
            logger.debug("Azure get_resources VM failed: %s", exc)

        # SQL Servers
        try:
            from azure.mgmt.sql import SqlManagementClient
            sql = SqlManagementClient(cred, sub_id)
            for server in sql.servers.list():
                resources.append({
                    "id": server.id or "", "name": server.name or "",
                    "type": "Microsoft.Sql/servers",
                    "location": server.location or "",
                    "config": {
                        "public_network_access": str(getattr(server, "public_network_access", "") or ""),
                        "minimal_tls_version": str(getattr(server, "minimal_tls_version", "") or ""),
                        "admin_login": getattr(server, "administrator_login", None),
                    },
                })
        except Exception as exc:
            logger.debug("Azure get_resources SQL failed: %s", exc)

        # App Services
        try:
            from azure.mgmt.web import WebSiteManagementClient
            wc = WebSiteManagementClient(cred, sub_id)
            for app in wc.web_apps.list():
                resources.append({
                    "id": app.id or "", "name": app.name or "",
                    "type": "Microsoft.Web/sites",
                    "location": app.location or "",
                    "config": {
                        "https_only": getattr(app, "https_only", None),
                        "kind": getattr(app, "kind", None),
                        "state": getattr(app, "state", None),
                        "outbound_ip_addresses": getattr(app, "outbound_ip_addresses", None),
                    },
                })
        except Exception as exc:
            logger.debug("Azure get_resources AppService failed: %s", exc)

        # AKS Clusters
        try:
            from azure.mgmt.containerservice import ContainerServiceClient
            csc = ContainerServiceClient(cred, sub_id)
            for cluster in csc.managed_clusters.list():
                np = getattr(cluster, "network_profile", None)
                api_profile = getattr(cluster, "api_server_access_profile", None)
                resources.append({
                    "id": cluster.id or "", "name": cluster.name or "",
                    "type": "Microsoft.ContainerService/managedClusters",
                    "location": cluster.location or "",
                    "config": {
                        "kubernetes_version": getattr(cluster, "kubernetes_version", None),
                        "enable_rbac": getattr(cluster, "enable_rbac", None),
                        "network_policy": str(getattr(np, "network_policy", "") or "") if np else "",
                        "private_cluster": getattr(api_profile, "enable_private_cluster", None) if api_profile else None,
                    },
                })
        except Exception as exc:
            logger.debug("Azure get_resources AKS failed: %s", exc)

        # NSGs (security rules summary)
        try:
            from azure.mgmt.network import NetworkManagementClient
            nc = NetworkManagementClient(cred, sub_id)
            for nsg in nc.network_security_groups.list_all():
                inbound_allow_any = any(
                    r.direction == "Inbound" and r.access == "Allow" and
                    (getattr(r, "source_address_prefix", "") or "").lower() in ("*", "0.0.0.0/0", "internet", "any")
                    for r in (nsg.security_rules or [])
                )
                resources.append({
                    "id": nsg.id or "", "name": nsg.name or "",
                    "type": "Microsoft.Network/networkSecurityGroups",
                    "location": nsg.location or "",
                    "config": {
                        "rule_count": len(nsg.security_rules or []),
                        "has_internet_inbound_allow": inbound_allow_any,
                    },
                })
        except Exception as exc:
            logger.debug("Azure get_resources NSG failed: %s", exc)

        # Container Registries
        try:
            from azure.mgmt.containerregistry import ContainerRegistryManagementClient
            rc = ContainerRegistryManagementClient(cred, sub_id)
            for reg in rc.registries.list():
                resources.append({
                    "id": reg.id or "", "name": reg.name or "",
                    "type": "Microsoft.ContainerRegistry/registries",
                    "location": reg.location or "",
                    "config": {
                        "admin_user_enabled": getattr(reg, "admin_user_enabled", None),
                        "public_network_access": str(getattr(reg, "public_network_access", "") or ""),
                        "sku": str(getattr(getattr(reg, "sku", None), "name", "") or ""),
                    },
                })
        except Exception as exc:
            logger.debug("Azure get_resources ACR failed: %s", exc)

        return resources

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _port_in_range(port_range: str, port: int) -> bool:
        if port_range in ("*", "Any"):
            return True
        if "-" in port_range:
            lo, hi = port_range.split("-", 1)
            try:
                return int(lo) <= port <= int(hi)
            except ValueError:
                return False
        try:
            return int(port_range) == port
        except ValueError:
            return False

    def _nsg_exposes_port(self, rule, port: int) -> bool:
        single = getattr(rule, "destination_port_range", None) or ""
        multi = list(getattr(rule, "destination_port_ranges", None) or [])
        return any(self._port_in_range(r, port) for r in [single] + multi if r)

    # ── Defender for Cloud (opportunistic) ───────────────────────────────────

    def _defender_assessments(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            sc = SecurityCenter(cred, sub_id)
            for a in sc.assessments.list(f"/subscriptions/{sub_id}"):
                if not (a.status and a.status.code in ("Unhealthy", "NotHealthy")):
                    continue
                sev = SEVERITY_MAP.get(getattr(a, "severity", "Medium"), FindingSeverity.MEDIUM)
                title = a.display_name or a.name
                findings.append(ConnectorFinding(
                    title=title,
                    description=getattr(a, "description", ""),
                    severity=sev,
                    resource_id=str(a.resource_details.id) if a.resource_details else "",
                    resource_type="AzureResource",
                    control_id=NIST_CONTROL_MAP.get(title, ""),
                    remediation=getattr(a, "remediation_description", ""),
                    framework="azure_security_benchmark",
                    control_mappings=defender_mappings(title),
                ))
        except Exception as exc:
            logger.info("Defender for Cloud assessments unavailable (not enabled?): %s", exc)
        return findings

    def _defender_sub_assessments(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            sc = SecurityCenter(cred, sub_id)
            for sa in sc.sub_assessments.list_all(f"/subscriptions/{sub_id}"):
                add_props = getattr(sa, "additional_data", None) or {}
                cve = ""
                if hasattr(add_props, "cve"):
                    cve = str(add_props.cve or "")
                cvss = None
                if hasattr(add_props, "cvss"):
                    try:
                        cvss = float((add_props.cvss or {}).get("3.0", {}).get("base", 0) or 0) or None
                    except Exception:
                        pass
                rid = ""
                if hasattr(sa, "resource_details") and sa.resource_details:
                    rid = str(sa.resource_details.id)
                findings.append(ConnectorFinding(
                    title=sa.display_name or "Vulnerability",
                    description=getattr(sa, "description", ""),
                    severity=FindingSeverity.HIGH,
                    resource_id=rid,
                    resource_type="VM",
                    cve_id=cve,
                    cvss_score=cvss or 0.0,
                    framework="cve",
                ))
        except Exception as exc:
            logger.info("Defender sub-assessments unavailable: %s", exc)
        return findings

    # ── NSG rules ─────────────────────────────────────────────────────────────

    def _check_nsg_rules(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.network import NetworkManagementClient
            nc = NetworkManagementClient(cred, sub_id)
            for nsg in nc.network_security_groups.list_all():
                for rule in (nsg.security_rules or []):
                    if rule.direction != "Inbound" or rule.access != "Allow":
                        continue
                    src = (getattr(rule, "source_address_prefix", "") or "").lower()
                    if src not in ("*", "0.0.0.0/0", "internet", "any"):
                        continue
                    for port, (svc, control, sev) in RISKY_PORTS.items():
                        if self._nsg_exposes_port(rule, port):
                            findings.append(ConnectorFinding(
                                title=f"NSG '{nsg.name}' allows unrestricted inbound {svc} (port {port})",
                                description=(
                                    f"Rule '{rule.name}' in NSG '{nsg.name}' permits inbound "
                                    f"{svc} traffic on port {port} from any source address (0.0.0.0/0). "
                                    f"This exposes resources to brute-force and remote exploitation."
                                ),
                                severity=sev,
                                resource_id=nsg.id or "",
                                resource_type="Microsoft.Network/networkSecurityGroups",
                                control_id=control,
                                remediation=(
                                    f"Remove or restrict the rule '{rule.name}'. "
                                    f"Limit the source address prefix to known IP ranges or use Just-In-Time VM access."
                                ),
                                framework="nist",
                                control_mappings=nsg_port_mappings(port),
                            ))
        except ImportError:
            logger.warning("azure-mgmt-network not installed; skipping NSG checks")
        except Exception as exc:
            logger.warning("NSG rule scan failed: %s", exc)
        return findings

    # ── Storage accounts ──────────────────────────────────────────────────────

    def _check_storage_accounts(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.storage import StorageManagementClient
            sc = StorageManagementClient(cred, sub_id)
            for sa in sc.storage_accounts.list():
                name = sa.name or ""
                rid = sa.id or ""
                rtype = "Microsoft.Storage/storageAccounts"

                if not getattr(sa, "enable_https_traffic_only", True):
                    findings.append(ConnectorFinding(
                        title=f"Storage account '{name}' allows unencrypted HTTP traffic",
                        description="HTTPS-only is not enforced. Data in transit can be intercepted by a network attacker.",
                        severity=FindingSeverity.HIGH,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST SC-8",
                        remediation="Enable 'Secure transfer required' (enable_https_traffic_only) on the storage account.",
                        framework="nist",
                        control_mappings=mappings_for("storage-https-only"),
                    ))

                if getattr(sa, "allow_blob_public_access", False):
                    findings.append(ConnectorFinding(
                        title=f"Storage account '{name}' permits public blob access",
                        description="Anonymous public read access is allowed. Any container set to public exposes blobs without authentication.",
                        severity=FindingSeverity.HIGH,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST AC-3",
                        remediation="Set 'Allow Blob Public Access' to Disabled on the storage account.",
                        framework="nist",
                        control_mappings=mappings_for("storage-public-blob"),
                    ))

                min_tls = str(getattr(sa, "minimum_tls_version", "") or "")
                if min_tls and min_tls not in ("TLS1_2", "TLS1_3"):
                    findings.append(ConnectorFinding(
                        title=f"Storage account '{name}' permits outdated TLS ({min_tls})",
                        description=f"Minimum TLS version is {min_tls}. TLS 1.0 and 1.1 are deprecated and have known weaknesses.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST SC-8",
                        remediation="Set minimum TLS version to TLS 1.2 on the storage account.",
                        framework="nist",
                        control_mappings=mappings_for("storage-tls-version"),
                    ))
        except ImportError:
            logger.warning("azure-mgmt-storage not installed; skipping storage account checks")
        except Exception as exc:
            logger.warning("Storage account scan failed: %s", exc)
        return findings

    # ── Key Vault ─────────────────────────────────────────────────────────────

    def _check_key_vaults(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            kvc = KeyVaultManagementClient(cred, sub_id)
            for kv in kvc.vaults.list():
                rid = kv.id or ""
                name = kv.name or ""
                rtype = "Microsoft.KeyVault/vaults"
                props = getattr(kv, "properties", None)
                if not props:
                    continue
                if not getattr(props, "enable_soft_delete", True):
                    findings.append(ConnectorFinding(
                        title=f"Key Vault '{name}' has soft delete disabled",
                        description="Soft delete is disabled. Secrets, keys and certificates can be permanently deleted with no recovery window.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST CP-9",
                        remediation="Enable soft delete on the Key Vault to allow recovery of accidentally deleted objects.",
                        framework="nist",
                        control_mappings=mappings_for("keyvault-soft-delete"),
                    ))
                if not getattr(props, "enable_purge_protection", False):
                    findings.append(ConnectorFinding(
                        title=f"Key Vault '{name}' has purge protection disabled",
                        description="Purge protection is not enabled. A malicious insider can permanently destroy soft-deleted secrets before the retention period ends.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST CP-9",
                        remediation="Enable purge protection on the Key Vault.",
                        framework="nist",
                        control_mappings=mappings_for("keyvault-purge-protection"),
                    ))
        except ImportError:
            logger.warning("azure-mgmt-keyvault not installed; skipping Key Vault checks")
        except Exception as exc:
            logger.warning("Key Vault scan failed: %s", exc)
        return findings

    # ── RBAC ──────────────────────────────────────────────────────────────────

    def _check_rbac(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient
            auth = AuthorizationManagementClient(cred, sub_id)
            scope = f"/subscriptions/{sub_id}"
            owner_count = 0
            for ra in auth.role_assignments.list_for_scope(scope):
                role_def_id = (ra.role_definition_id or "").lower()
                if OWNER_ROLE_ID in role_def_id:
                    owner_count += 1
            if owner_count > 3:
                findings.append(ConnectorFinding(
                    title=f"Subscription has {owner_count} Owner role assignments",
                    description=(
                        f"{owner_count} principals hold the Owner role at subscription scope. "
                        "Excess Owner assignments increase the blast radius of a compromised account."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_id=scope,
                    resource_type="Microsoft.Authorization/roleAssignments",
                    control_id="NIST AC-6",
                    remediation="Review and reduce Owner role assignments. Use least-privilege roles (Reader, Contributor) where full Owner access is not required.",
                    framework="nist",
                    control_mappings=mappings_for("rbac-excess-owners"),
                ))
        except ImportError:
            logger.warning("azure-mgmt-authorization not installed; skipping RBAC checks")
        except Exception as exc:
            logger.warning("RBAC scan failed: %s", exc)
        return findings

    # ── Activity log / diagnostics ────────────────────────────────────────────

    def _check_activity_logs(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            mc = MonitorManagementClient(cred, sub_id)
            scope = f"/subscriptions/{sub_id}"
            diag_settings = list(mc.diagnostic_settings.list(scope))
            if not diag_settings:
                findings.append(ConnectorFinding(
                    title="Azure Activity Log has no diagnostic settings configured",
                    description=(
                        "No diagnostic setting exports the subscription Activity Log. "
                        "Administrative and control-plane operations are not retained "
                        "in a SIEM or storage account for audit review."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    resource_id=scope,
                    resource_type="Microsoft.Subscription",
                    control_id="NIST AU-2",
                    remediation="Add a diagnostic setting to export the Activity Log to Log Analytics Workspace, Event Hub, or a Storage Account.",
                    framework="nist",
                    control_mappings=mappings_for("activity-log-no-diag-settings"),
                ))
        except Exception as exc:
            logger.debug("Activity log diagnostic check failed: %s", exc)
        return findings

    # ── VM security ────────────────────────────────────────────────────────────

    def _check_vm_security(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.compute import ComputeManagementClient
            cc = ComputeManagementClient(cred, sub_id)
            for vm in cc.virtual_machines.list_all():
                rid = vm.id or ""
                name = vm.name or rid
                rtype = "Microsoft.Compute/virtualMachines"

                # Check OS disk encryption
                sp = getattr(vm, "storage_profile", None)
                os_disk = getattr(sp, "os_disk", None) if sp else None
                enc_settings = getattr(os_disk, "encryption_settings", None) if os_disk else None
                disk_encrypted = bool(enc_settings and getattr(enc_settings, "enabled", False))
                if not disk_encrypted:
                    findings.append(ConnectorFinding(
                        title=f"VM '{name}' OS disk is not encrypted with ADE",
                        description="Azure Disk Encryption is not enabled on the VM OS disk. If the disk is detached it can be mounted and read without authentication.",
                        severity=FindingSeverity.HIGH,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST SC-28",
                        remediation="Enable Azure Disk Encryption on the VM using the AzureDiskEncryption extension.",
                        framework="nist",
                        control_mappings=mappings_for("vm-os-disk-not-encrypted"),
                    ))

                # Check for endpoint protection extension
                rg = rid.split("/")[4] if rid.count("/") >= 5 else ""
                if rg:
                    try:
                        exts = list(cc.virtual_machine_extensions.list(rg, name))
                        has_ep = any(
                            (getattr(e, "virtual_machine_extension_type", "") or "").split(".")[-1] in EP_EXTENSION_TYPES
                            for e in exts
                        )
                        if not has_ep:
                            findings.append(ConnectorFinding(
                                title=f"VM '{name}' has no detected endpoint protection extension",
                                description=(
                                    "No known endpoint protection or MDE extension was found on the VM. "
                                    "The machine may be unprotected against malware and active threats."
                                ),
                                severity=FindingSeverity.MEDIUM,
                                resource_id=rid, resource_type=rtype,
                                control_id="NIST SI-3",
                                remediation="Install Microsoft Defender for Endpoint (MDE) or an equivalent endpoint protection solution.",
                                framework="nist",
                                control_mappings=mappings_for("vm-no-endpoint-protection"),
                            ))
                    except Exception:
                        pass
        except ImportError:
            logger.warning("azure-mgmt-compute not installed; skipping VM security checks")
        except Exception as exc:
            logger.warning("VM security scan failed: %s", exc)
        return findings

    # ── App Service ───────────────────────────────────────────────────────────

    def _check_app_service(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.web import WebSiteManagementClient
            wc = WebSiteManagementClient(cred, sub_id)
            for app in wc.web_apps.list():
                rid = app.id or ""
                name = app.name or rid
                rtype = "Microsoft.Web/sites"
                site_config = None
                try:
                    rg = rid.split("/")[4] if rid.count("/") >= 5 else ""
                    if rg:
                        site_config = wc.web_apps.get_configuration(rg, name)
                except Exception:
                    pass

                # HTTPS only
                if not getattr(app, "https_only", True):
                    findings.append(ConnectorFinding(
                        title=f"App Service '{name}' allows unencrypted HTTP traffic",
                        description="HTTPS-only mode is disabled. HTTP requests are not redirected to HTTPS, exposing data in transit.",
                        severity=FindingSeverity.HIGH,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST SC-8",
                        remediation="Enable HTTPS-only mode on the App Service.",
                        framework="nist",
                        control_mappings=mappings_for("appservice-https-only"),
                    ))

                if site_config:
                    # Min TLS version
                    min_tls = str(getattr(site_config, "min_tls_version", "") or "")
                    if min_tls and min_tls not in ("1.2", "1.3"):
                        findings.append(ConnectorFinding(
                            title=f"App Service '{name}' permits outdated TLS ({min_tls})",
                            description=f"Minimum TLS version is {min_tls}. TLS < 1.2 has known cryptographic weaknesses.",
                            severity=FindingSeverity.MEDIUM,
                            resource_id=rid, resource_type=rtype,
                            control_id="NIST SC-8",
                            remediation="Set minimum TLS version to 1.2 in App Service configuration.",
                            framework="nist",
                            control_mappings=mappings_for("appservice-tls-version"),
                        ))
                    # Remote debugging
                    if getattr(site_config, "remote_debugging_enabled", False):
                        findings.append(ConnectorFinding(
                            title=f"App Service '{name}' has remote debugging enabled",
                            description="Remote debugging is enabled on the production App Service. This opens an unauthenticated debug port that grants full code execution access.",
                            severity=FindingSeverity.HIGH,
                            resource_id=rid, resource_type=rtype,
                            control_id="NIST CM-7",
                            remediation="Disable remote debugging in App Service configuration.",
                            framework="nist",
                            control_mappings=mappings_for("appservice-remote-debug"),
                        ))
                    # FTP state
                    ftp_state = str(getattr(site_config, "ftp_state", "") or "")
                    if ftp_state and ftp_state.lower() not in ("ftpsdisabled", "disabled"):
                        findings.append(ConnectorFinding(
                            title=f"App Service '{name}' has FTP deployment enabled",
                            description=f"FTP/FTPS deployment is set to '{ftp_state}'. Plain FTP transmits credentials in clear text.",
                            severity=FindingSeverity.MEDIUM,
                            resource_id=rid, resource_type=rtype,
                            control_id="NIST SC-8",
                            remediation="Set FTP state to 'FtpsOnly' or 'Disabled' in App Service configuration.",
                            framework="nist",
                            control_mappings=mappings_for("appservice-ftp"),
                        ))
        except ImportError:
            logger.warning("azure-mgmt-web not installed; skipping App Service checks")
        except Exception as exc:
            logger.warning("App Service scan failed: %s", exc)
        return findings

    # ── SQL Databases ─────────────────────────────────────────────────────────

    def _check_sql_databases(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.sql import SqlManagementClient
            sc = SqlManagementClient(cred, sub_id)
            for server in sc.servers.list():
                srv_name = server.name or ""
                srv_rid = server.id or ""
                rg = srv_rid.split("/")[4] if srv_rid.count("/") >= 5 else ""
                rtype = "Microsoft.Sql/servers"

                # Public network access
                pub = str(getattr(server, "public_network_access", "") or "")
                if pub.lower() == "enabled":
                    findings.append(ConnectorFinding(
                        title=f"SQL Server '{srv_name}' has public network access enabled",
                        description="Public network access is enabled on the SQL Server. The server endpoint is reachable from the internet.",
                        severity=FindingSeverity.HIGH,
                        resource_id=srv_rid, resource_type=rtype,
                        control_id="NIST SC-7",
                        remediation="Disable public network access and use Private Endpoint for SQL Server connectivity.",
                        framework="nist",
                        control_mappings=mappings_for("sql-public-network"),
                    ))

                if rg:
                    # Firewall rule 0.0.0.0 (Allow all Azure IPs / unrestricted)
                    try:
                        for fw_rule in sc.firewall_rules.list_by_server(rg, srv_name):
                            if getattr(fw_rule, "start_ip_address", "") == "0.0.0.0" and getattr(fw_rule, "end_ip_address", "") == "255.255.255.255":
                                findings.append(ConnectorFinding(
                                    title=f"SQL Server '{srv_name}' firewall allows all IPs (0.0.0.0–255.255.255.255)",
                                    description=f"Firewall rule '{fw_rule.name}' permits connections from any IP address. This exposes the SQL Server to brute-force and exploitation from the internet.",
                                    severity=FindingSeverity.CRITICAL,
                                    resource_id=srv_rid, resource_type=rtype,
                                    control_id="NIST SC-7",
                                    remediation="Remove the catch-all firewall rule and restrict access to known IP ranges or use Private Endpoint.",
                                    framework="nist",
                                    control_mappings=mappings_for("sql-firewall-open"),
                                ))
                    except Exception:
                        pass

                    # Per-DB checks: TDE
                    try:
                        for db in sc.databases.list_by_server(rg, srv_name):
                            db_name = db.name or ""
                            db_rid = db.id or ""
                            if db_name == "master":
                                continue
                            try:
                                tde = sc.transparent_data_encryptions.get(rg, srv_name, db_name, "current")
                                if str(getattr(tde, "state", "") or "").lower() != "enabled":
                                    findings.append(ConnectorFinding(
                                        title=f"SQL Database '{srv_name}/{db_name}' has TDE disabled",
                                        description="Transparent Data Encryption is not enabled. Data at rest on the database and backups is not encrypted.",
                                        severity=FindingSeverity.HIGH,
                                        resource_id=db_rid,
                                        resource_type="Microsoft.Sql/servers/databases",
                                        control_id="NIST SC-28",
                                        remediation="Enable Transparent Data Encryption on the SQL database.",
                                        framework="nist",
                                        control_mappings=mappings_for("sql-tde"),
                                    ))
                            except Exception:
                                pass
                    except Exception:
                        pass
        except ImportError:
            logger.warning("azure-mgmt-sql not installed; skipping SQL database checks")
        except Exception as exc:
            logger.warning("SQL database scan failed: %s", exc)
        return findings

    # ── AKS Clusters ──────────────────────────────────────────────────────────

    def _check_aks_clusters(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.containerservice import ContainerServiceClient
            cc = ContainerServiceClient(cred, sub_id)
            for cluster in cc.managed_clusters.list():
                rid = cluster.id or ""
                name = cluster.name or rid
                rtype = "Microsoft.ContainerService/managedClusters"

                # RBAC
                if not getattr(cluster, "enable_rbac", True):
                    findings.append(ConnectorFinding(
                        title=f"AKS cluster '{name}' has Kubernetes RBAC disabled",
                        description="Kubernetes Role-Based Access Control is disabled. All authenticated users have unrestricted access to cluster resources.",
                        severity=FindingSeverity.HIGH,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST AC-6",
                        remediation="Enable Kubernetes RBAC on the AKS cluster.",
                        framework="nist",
                        control_mappings=mappings_for("aks-rbac-disabled"),
                    ))

                # Private cluster
                api_profile = getattr(cluster, "api_server_access_profile", None)
                is_private = getattr(api_profile, "enable_private_cluster", False) if api_profile else False
                if not is_private:
                    findings.append(ConnectorFinding(
                        title=f"AKS cluster '{name}' has public API server endpoint",
                        description="The Kubernetes API server is accessible from the public internet. An exposed API server increases the attack surface for credential stuffing and exploitation.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST SC-7",
                        remediation="Enable private cluster mode to restrict API server access to within the VNet.",
                        framework="nist",
                        control_mappings=mappings_for("aks-public-api"),
                    ))

                # Network policy
                np = getattr(cluster, "network_profile", None)
                net_policy = str(getattr(np, "network_policy", "") or "") if np else ""
                if not net_policy or net_policy.lower() == "none":
                    findings.append(ConnectorFinding(
                        title=f"AKS cluster '{name}' has no network policy configured",
                        description="No Kubernetes network policy is set. All pods can communicate with each other without restriction, allowing lateral movement if a pod is compromised.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST SC-7",
                        remediation="Configure a network policy (Azure or Calico) to restrict inter-pod traffic to required paths only.",
                        framework="nist",
                        control_mappings=mappings_for("aks-no-network-policy"),
                    ))
        except ImportError:
            logger.warning("azure-mgmt-containerservice not installed; skipping AKS checks")
        except Exception as exc:
            logger.warning("AKS cluster scan failed: %s", exc)
        return findings

    # ── Container Registry ────────────────────────────────────────────────────

    def _check_container_registry(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.containerregistry import ContainerRegistryManagementClient
            rc = ContainerRegistryManagementClient(cred, sub_id)
            for reg in rc.registries.list():
                rid = reg.id or ""
                name = reg.name or rid
                rtype = "Microsoft.ContainerRegistry/registries"

                # Admin user
                if getattr(reg, "admin_user_enabled", False):
                    findings.append(ConnectorFinding(
                        title=f"Container Registry '{name}' has admin user enabled",
                        description="The legacy admin account is enabled. Admin credentials are static, shared, and not auditable — use Azure AD identities instead.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST AC-2",
                        remediation="Disable admin user and use Azure RBAC with managed identities for registry authentication.",
                        framework="nist",
                        control_mappings=mappings_for("acr-admin-enabled"),
                    ))

                # Public network access
                pub = str(getattr(reg, "public_network_access", "") or "")
                if pub.lower() == "enabled":
                    findings.append(ConnectorFinding(
                        title=f"Container Registry '{name}' is publicly accessible",
                        description="Public network access is enabled. The registry endpoint accepts connections from any IP address on the internet.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=rid, resource_type=rtype,
                        control_id="NIST SC-7",
                        remediation="Disable public network access and use Private Endpoint or service endpoints for registry access.",
                        framework="nist",
                        control_mappings=mappings_for("acr-public-access"),
                    ))
        except ImportError:
            logger.warning("azure-mgmt-containerregistry not installed; skipping Container Registry checks")
        except Exception as exc:
            logger.warning("Container Registry scan failed: %s", exc)
        return findings

    # ── Public IPs ────────────────────────────────────────────────────────────

    def _check_public_ips(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.network import NetworkManagementClient
            nc = NetworkManagementClient(cred, sub_id)
            for pip in nc.public_ip_addresses.list_all():
                if getattr(pip, "ip_configuration", None) is None:
                    rid = pip.id or ""
                    name = pip.name or rid
                    findings.append(ConnectorFinding(
                        title=f"Public IP '{name}' is unassociated (idle resource)",
                        description="This public IP address is not attached to any resource. Unmanaged public IPs add to your attack surface and incur unnecessary cost.",
                        severity=FindingSeverity.LOW,
                        resource_id=rid,
                        resource_type="Microsoft.Network/publicIPAddresses",
                        control_id="NIST CM-7",
                        remediation="Delete unneeded public IP addresses or associate them with the intended resource.",
                        framework="nist",
                        control_mappings=mappings_for("network-unattached-pip"),
                    ))
        except ImportError:
            logger.warning("azure-mgmt-network not installed; skipping public IP checks")
        except Exception as exc:
            logger.warning("Public IP scan failed: %s", exc)
        return findings

    # ── Log Analytics ─────────────────────────────────────────────────────────

    def _check_monitor_log_analytics(self, cred, sub_id: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from azure.mgmt.loganalytics import LogAnalyticsManagementClient
            lac = LogAnalyticsManagementClient(cred, sub_id)
            for ws in lac.workspaces.list():
                rid = ws.id or ""
                name = ws.name or rid
                retention = getattr(ws, "retention_in_days", None)
                if retention is not None and retention < 90:
                    findings.append(ConnectorFinding(
                        title=f"Log Analytics workspace '{name}' has short retention ({retention} days)",
                        description=f"Data retention is set to {retention} days. Security investigations typically require 90+ days of log history; many compliance frameworks mandate 365 days.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=rid,
                        resource_type="Microsoft.OperationalInsights/workspaces",
                        control_id="NIST AU-11",
                        remediation="Increase Log Analytics workspace retention to at least 90 days (recommended: 365 days for compliance).",
                        framework="nist",
                        control_mappings=mappings_for("monitor-log-retention"),
                    ))
        except ImportError:
            logger.warning("azure-mgmt-loganalytics not installed; skipping Log Analytics checks")
        except Exception as exc:
            logger.warning("Log Analytics scan failed: %s", exc)
        return findings

    # ── Public scan methods ───────────────────────────────────────────────────

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        """
        Run all configuration checks:
        1. Defender for Cloud assessments (if enabled)
        2. Direct ARM checks: NSG rules, storage accounts, Key Vault, RBAC, activity log,
           App Service, SQL databases, AKS, Container Registry, public IPs, Log Analytics
        """
        cred = self._build_credential()
        sub_id = self.credentials["subscription_id"]
        findings: List[ConnectorFinding] = []

        findings += self._defender_assessments(cred, sub_id)
        findings += self._check_nsg_rules(cred, sub_id)
        findings += self._check_storage_accounts(cred, sub_id)
        findings += self._check_key_vaults(cred, sub_id)
        findings += self._check_rbac(cred, sub_id)
        findings += self._check_activity_logs(cred, sub_id)
        findings += self._check_app_service(cred, sub_id)
        findings += self._check_sql_databases(cred, sub_id)
        findings += self._check_aks_clusters(cred, sub_id)
        findings += self._check_container_registry(cred, sub_id)
        findings += self._check_public_ips(cred, sub_id)
        findings += self._check_monitor_log_analytics(cred, sub_id)
        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        """
        Pull CVE-level findings from Defender for Cloud sub-assessments,
        then add direct VM disk encryption and endpoint-protection checks.
        """
        cred = self._build_credential()
        sub_id = self.credentials["subscription_id"]
        findings: List[ConnectorFinding] = []

        findings += self._defender_sub_assessments(cred, sub_id)
        findings += self._check_vm_security(cred, sub_id)
        return findings

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        cred = self._build_credential()
        subscription_id = self.credentials["subscription_id"]
        sc = SecurityCenter(cred, subscription_id)
        results: Dict[str, Any] = {}
        try:
            standards = sc.regulatory_compliance_standards.list(subscription_id)
            for std in standards:
                if framework.lower() in std.name.lower():
                    controls = sc.regulatory_compliance_controls.list(
                        subscription_id, std.name
                    )
                    for ctrl in controls:
                        results[ctrl.name] = {
                            "state": ctrl.state,
                            "passed": ctrl.passed_assessments_count,
                            "failed": ctrl.failed_assessments_count,
                        }
        except Exception:
            pass
        return results
