"""Invicti (Netsparker) connector — test connection via REST API."""
import base64
import httpx
import logging
from typing import Any, Dict, List
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult

logger = logging.getLogger(__name__)


class InvictiConnector(BaseConnector):

    async def test_connection(self) -> ConnectorTestResult:
        api_url = self.credentials.get("api_url", "https://www.invicti.com/api/1.0").rstrip("/")
        api_token = self.credentials.get("api_token", "")
        username = self.credentials.get("username", "")
        if not api_token:
            return ConnectorTestResult(success=False, message="Invicti requires 'api_token' in credentials")
        cred_str = f"{username}:{api_token}" if username else f":{api_token}"
        encoded = base64.b64encode(cred_str.encode()).decode()
        headers = {"Authorization": f"Basic {encoded}", "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(f"{api_url}/account/me", headers=headers)
                if resp.status_code == 401:
                    return ConnectorTestResult(success=False, message="Authentication failed — check api_token")
                if resp.status_code == 200:
                    data = resp.json()
                    return ConnectorTestResult(
                        success=True,
                        message="Connected to Invicti successfully",
                        details={"email": data.get("Email", ""), "api_url": api_url},
                    )
                return ConnectorTestResult(success=False, message=f"Invicti API returned HTTP {resp.status_code}")
        except httpx.ConnectError as exc:
            return ConnectorTestResult(success=False, message=f"Cannot reach Invicti API — {exc}")
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
