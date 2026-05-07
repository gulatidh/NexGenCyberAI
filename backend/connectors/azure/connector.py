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
        subscription_id = self.credentials["subscription_id"]
        rm = ResourceManagementClient(cred, subscription_id)
        resources = []
        for r in rm.resources.list():
            resources.append({
                "id": r.id,
                "name": r.name,
                "type": r.type,
                "location": r.location,
                "tags": r.tags or {},
            })
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
                            ))
                    except Exception:
                        pass
        except ImportError:
            logger.warning("azure-mgmt-compute not installed; skipping VM security checks")
        except Exception as exc:
            logger.warning("VM security scan failed: %s", exc)
        return findings

    # ── Public scan methods ───────────────────────────────────────────────────

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        """
        Run all configuration checks:
        1. Defender for Cloud assessments (if enabled)
        2. Direct ARM checks: NSG rules, storage accounts, Key Vault, RBAC, activity log
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
