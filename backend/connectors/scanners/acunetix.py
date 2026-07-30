"""Acunetix Enterprise connector — test connection via REST API."""
import httpx
import logging
from typing import Any, Dict, List
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult

logger = logging.getLogger(__name__)


class AcunetixConnector(BaseConnector):

    async def test_connection(self) -> ConnectorTestResult:
        host = self.credentials.get("host", "").rstrip("/")
        api_key = self.credentials.get("api_key", "")
        port = self.config.get("port", 3443)
        if not host or not api_key:
            return ConnectorTestResult(success=False, message="Acunetix requires 'host' and 'api_key'")
        base = f"{host}:{port}/api/v1"
        headers = {"X-Auth": api_key, "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(verify=False, timeout=20) as client:
                resp = await client.get(f"{base}/me", headers=headers)
                if resp.status_code == 401:
                    return ConnectorTestResult(success=False, message="Authentication failed — check API key")
                if resp.status_code == 200:
                    data = resp.json()
                    return ConnectorTestResult(
                        success=True,
                        message=f"Connected to Acunetix at {host}:{port}",
                        details={"email": data.get("email", ""), "host": host},
                    )
                return ConnectorTestResult(success=False, message=f"Acunetix API returned HTTP {resp.status_code}")
        except httpx.ConnectError as exc:
            return ConnectorTestResult(success=False, message=f"Cannot reach Acunetix host — {exc}")
        except Exception as exc:
            return ConnectorTestResult(success=False, message=f"Connection error: {exc}")

    async def get_resources(self) -> List[Dict[str, Any]]:
        return []

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        return []

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
