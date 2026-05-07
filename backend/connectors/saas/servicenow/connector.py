"""
NexGenCyberAI - ServiceNow Connector
Reads incidents, change requests, and vulnerability items via REST API.
Auth: Basic (username/password) or OAuth2 client credentials.
"""
from typing import Any, Dict, List
import httpx
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

PRIORITY_MAP = {
    "1": FindingSeverity.CRITICAL,
    "2": FindingSeverity.HIGH,
    "3": FindingSeverity.MEDIUM,
    "4": FindingSeverity.LOW,
    "5": FindingSeverity.INFO,
}


class ServiceNowConnector(BaseConnector):

    @property
    def _base_url(self):
        return self.credentials["instance_url"].rstrip("/")

    def _auth(self):
        if tok := self.credentials.get("oauth_token"):
            return {"Authorization": f"Bearer {tok}"}
        user = self.credentials["username"]
        pwd = self.credentials["password"]
        return None  # httpx basic auth tuple handled separately

    async def _get(self, path: str, params: Dict = {}) -> Dict:
        url = f"{self._base_url}{path}"
        timeout = httpx.Timeout(30)
        async with httpx.AsyncClient(timeout=timeout) as client:
            if tok := self.credentials.get("oauth_token"):
                resp = await client.get(url, headers={"Authorization": f"Bearer {tok}"}, params=params)
            else:
                resp = await client.get(
                    url,
                    auth=(self.credentials["username"], self.credentials["password"]),
                    params=params,
                )
        resp.raise_for_status()
        return resp.json()

    async def test_connection(self) -> ConnectorTestResult:
        try:
            data = await self._get("/api/now/table/sys_user", {"sysparm_limit": "1"})
            return ConnectorTestResult(success=True, message="ServiceNow connection successful", details=data)
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    async def get_resources(self) -> List[Dict[str, Any]]:
        data = await self._get("/api/now/table/cmdb_ci", {"sysparm_limit": "100"})
        return data.get("result", [])

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        findings = []
        try:
            data = await self._get(
                "/api/now/table/incident",
                {"sysparm_query": "active=true^category=security", "sysparm_limit": "200"},
            )
            for inc in data.get("result", []):
                sev = PRIORITY_MAP.get(inc.get("priority", "3"), FindingSeverity.MEDIUM)
                findings.append(ConnectorFinding(
                    title=inc.get("short_description", "Incident"),
                    description=inc.get("description", ""),
                    severity=sev,
                    resource_id=inc.get("sys_id", ""),
                    resource_type="ServiceNow Incident",
                    framework="itsm",
                    remediation=inc.get("close_notes", ""),
                ))
        except Exception:
            pass
        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        findings = []
        try:
            data = await self._get(
                "/api/now/table/sn_vul_vulnerable_item",
                {"sysparm_query": "state!=closed", "sysparm_limit": "200"},
            )
            for item in data.get("result", []):
                findings.append(ConnectorFinding(
                    title=item.get("vulnerability", {}).get("display_value", "Vulnerability"),
                    description=item.get("comments", ""),
                    severity=PRIORITY_MAP.get(str(item.get("risk", "3")), FindingSeverity.MEDIUM),
                    resource_id=item.get("cmdb_ci", {}).get("value", ""),
                    resource_type="CMDB CI",
                    cve_id=item.get("vulnerability", {}).get("display_value", ""),
                    framework="cve",
                ))
        except Exception:
            pass
        return findings

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
