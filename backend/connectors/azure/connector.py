"""
NexGenCyberAI - Azure Connector
Connects via Azure SDK using Service Principal or Managed Identity.
Pulls Security Center / Defender for Cloud findings, resource config, and policy states.
"""
from typing import Any, Dict, List
from azure.identity import ClientSecretCredential, ManagedIdentityCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.monitor import MonitorManagementClient
import asyncio

from ..base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity


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


class AzureConnector(BaseConnector):

    def _build_credential(self):
        if self.credentials.get("use_managed_identity"):
            return ManagedIdentityCredential()
        return ClientSecretCredential(
            tenant_id=self.credentials["tenant_id"],
            client_id=self.credentials["client_id"],
            client_secret=self.credentials["client_secret"],
        )

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

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        cred = self._build_credential()
        subscription_id = self.credentials["subscription_id"]
        sc = SecurityCenter(cred, subscription_id)
        findings = []
        try:
            assessments = sc.assessments.list(f"/subscriptions/{subscription_id}")
            for a in assessments:
                if a.status and a.status.code in ("Unhealthy", "NotHealthy"):
                    sev = SEVERITY_MAP.get(
                        getattr(a, "severity", "Medium"), FindingSeverity.MEDIUM
                    )
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
        except Exception:
            # Defender for Cloud may not be enabled on all subscriptions
            pass
        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        """Pull Defender for Cloud sub-assessments (CVE-level findings)."""
        cred = self._build_credential()
        subscription_id = self.credentials["subscription_id"]
        sc = SecurityCenter(cred, subscription_id)
        findings = []
        try:
            sub_assessments = sc.sub_assessments.list_all(
                f"/subscriptions/{subscription_id}"
            )
            for sa in sub_assessments:
                cve = getattr(sa, "id", "")
                findings.append(ConnectorFinding(
                    title=sa.display_name or "Vulnerability",
                    description=getattr(sa, "description", ""),
                    severity=FindingSeverity.HIGH,
                    resource_id=str(sa.resource_details.id) if hasattr(sa, "resource_details") and sa.resource_details else "",
                    resource_type="VM",
                    cve_id=cve,
                    framework="cve",
                ))
        except Exception:
            pass
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
