"""
NexGenCyberAI - GCP Connector
Uses google-cloud-securitycenter and google-cloud-asset APIs.
Auth via Service Account JSON key or Workload Identity.
"""
from typing import Any, Dict, List
from google.cloud import securitycenter_v1, asset_v1
from google.oauth2 import service_account
import json

from ..base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

SEVERITY_MAP = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
}


class GCPConnector(BaseConnector):

    def _credentials(self):
        if sa_json := self.credentials.get("service_account_json"):
            info = json.loads(sa_json) if isinstance(sa_json, str) else sa_json
            return service_account.Credentials.from_service_account_info(
                info,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
        return None  # use ADC

    async def test_connection(self) -> ConnectorTestResult:
        try:
            creds = self._credentials()
            project_id = self.credentials["project_id"]
            client = asset_v1.AssetServiceClient(credentials=creds)
            parent = f"projects/{project_id}"
            resp = client.list_assets(request={"parent": parent, "page_size": 1})
            return ConnectorTestResult(
                success=True,
                message=f"Connected to GCP project {project_id}",
                details={"project_id": project_id},
            )
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    async def get_resources(self) -> List[Dict[str, Any]]:
        creds = self._credentials()
        project_id = self.credentials["project_id"]
        client = asset_v1.AssetServiceClient(credentials=creds)
        resources = []
        request = asset_v1.ListAssetsRequest(
            parent=f"projects/{project_id}",
            asset_types=["compute.googleapis.com/Instance", "storage.googleapis.com/Bucket"],
            content_type=asset_v1.ContentType.RESOURCE,
        )
        for asset in client.list_assets(request=request):
            resources.append({
                "id": asset.name,
                "name": asset.name.split("/")[-1],
                "type": asset.asset_type,
                "project": project_id,
            })
        return resources

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        creds = self._credentials()
        project_id = self.credentials["project_id"]
        sc_client = securitycenter_v1.SecurityCenterClient(credentials=creds)
        org_id = self.credentials.get("org_id", "")
        findings = []
        try:
            parent = f"organizations/{org_id}/sources/-" if org_id else f"projects/{project_id}/sources/-"
            request = securitycenter_v1.ListFindingsRequest(
                parent=parent,
                filter='state="ACTIVE"',
            )
            for result in sc_client.list_findings(request=request):
                f = result.finding
                sev = SEVERITY_MAP.get(str(f.severity.name), FindingSeverity.MEDIUM)
                findings.append(ConnectorFinding(
                    title=f.category,
                    description=f.description if hasattr(f, "description") else "",
                    severity=sev,
                    resource_id=f.resource_name,
                    resource_type=f.resource_name.split("/")[4] if "/" in f.resource_name else "",
                    framework="gcp_cis_benchmark",
                ))
        except Exception:
            pass
        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        # GCP uses Container Analysis API for CVE findings
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
