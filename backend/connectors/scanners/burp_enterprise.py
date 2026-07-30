"""Burp Suite Enterprise Edition connector — test connection via REST API."""
import httpx
import logging
from typing import Any, Dict, List
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult

logger = logging.getLogger(__name__)


class BurpEnterpriseConnector(BaseConnector):

    async def test_connection(self) -> ConnectorTestResult:
        host = self.credentials.get("host", "").rstrip("/")
        api_key = self.credentials.get("api_key", "")
        if not host or not api_key:
            return ConnectorTestResult(success=False, message="Burp Suite Enterprise requires 'host' and 'api_key'")
        try:
            async with httpx.AsyncClient(verify=False, timeout=20) as client:
                resp = await client.get(
                    f"{host}/api/v1/system/information",
                    headers={"Authorization": api_key},
                )
                if resp.status_code == 401:
                    return ConnectorTestResult(success=False, message="Authentication failed — check API key")
                if resp.status_code == 404:
                    # Try alternate endpoint
                    resp = await client.get(
                        f"{host}/api/v1/scan-configurations",
                        headers={"Authorization": api_key},
                    )
                if resp.status_code in (200, 201):
                    return ConnectorTestResult(
                        success=True,
                        message=f"Connected to Burp Suite Enterprise at {host}",
                        details={"host": host},
                    )
                return ConnectorTestResult(success=False, message=f"Burp API returned HTTP {resp.status_code}")
        except httpx.ConnectError as exc:
            return ConnectorTestResult(success=False, message=f"Cannot reach Burp Enterprise host — {exc}")
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
