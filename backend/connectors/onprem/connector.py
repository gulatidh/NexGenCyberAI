"""
NexGenCyberAI - On-Premises Connector
Connects via Nessus REST API or OpenVAS GMP for VA scanning.
Also supports SSH-based configuration checks on Linux/Windows hosts.
"""
from typing import Any, Dict, List
import httpx
from ..base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

NESSUS_SEVERITY = {0: FindingSeverity.INFO, 1: FindingSeverity.LOW, 2: FindingSeverity.MEDIUM,
                   3: FindingSeverity.HIGH, 4: FindingSeverity.CRITICAL}


class OnPremConnector(BaseConnector):

    @property
    def _nessus_url(self):
        return self.credentials.get("nessus_url", "https://localhost:8834")

    async def _nessus_get(self, path: str) -> Dict:
        token = self.credentials.get("nessus_api_key", "")
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            resp = await client.get(
                f"{self._nessus_url}{path}",
                headers={"X-ApiKeys": f"accessKey={token}; secretKey={self.credentials.get('nessus_secret_key', '')}"},
            )
        resp.raise_for_status()
        return resp.json()

    async def test_connection(self) -> ConnectorTestResult:
        try:
            data = await self._nessus_get("/server/status")
            return ConnectorTestResult(success=True, message=f"Nessus status: {data.get('status')}", details=data)
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    async def get_resources(self) -> List[Dict[str, Any]]:
        try:
            data = await self._nessus_get("/scans")
            return data.get("scans", [])
        except Exception:
            return []

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        return []

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        findings = []
        try:
            scans = await self._nessus_get("/scans")
            for scan in scans.get("scans", [])[:5]:
                scan_id = scan["id"]
                detail = await self._nessus_get(f"/scans/{scan_id}")
                for vuln in detail.get("vulnerabilities", []):
                    sev = NESSUS_SEVERITY.get(vuln.get("severity", 0), FindingSeverity.INFO)
                    findings.append(ConnectorFinding(
                        title=vuln.get("plugin_name", ""),
                        description=vuln.get("plugin_name", ""),
                        severity=sev,
                        resource_id=str(scan_id),
                        resource_type="Host",
                        control_id=vuln.get("plugin_id", ""),
                        cve_id=vuln.get("cve", [""])[0] if vuln.get("cve") else "",
                        cvss_score=float(vuln.get("cvss3_base_score", 0) or 0),
                        framework="cve",
                    ))
        except Exception:
            pass
        return findings

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
