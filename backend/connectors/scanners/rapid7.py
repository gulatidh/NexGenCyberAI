"""Rapid7 InsightVM connector — test connection via REST API."""
import httpx
import logging
from typing import Any, Dict, List
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult

logger = logging.getLogger(__name__)


class Rapid7Connector(BaseConnector):

    async def test_connection(self) -> ConnectorTestResult:
        host = self.credentials.get("host", "").rstrip("/")
        username = self.credentials.get("username", "")
        password = self.credentials.get("password", "")
        port = self.config.get("port", 3780)
        if not host or not username or not password:
            return ConnectorTestResult(success=False, message="Rapid7 InsightVM requires 'host', 'username', 'password'")
        base = f"{host}:{port}/api/3"
        try:
            async with httpx.AsyncClient(verify=False, timeout=20) as client:
                resp = await client.get(
                    f"{base}/administration/info",
                    auth=(username, password),
                )
                if resp.status_code == 401:
                    return ConnectorTestResult(success=False, message="Authentication failed — check username and password")
                if resp.status_code == 200:
                    data = resp.json()
                    return ConnectorTestResult(
                        success=True,
                        message=f"Connected to Rapid7 InsightVM at {host}:{port}",
                        details={"version": data.get("version", "unknown"), "host": host},
                    )
                return ConnectorTestResult(success=False, message=f"Rapid7 API returned HTTP {resp.status_code}")
        except httpx.ConnectError as exc:
            return ConnectorTestResult(success=False, message=f"Cannot reach Rapid7 host — {exc}")
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
