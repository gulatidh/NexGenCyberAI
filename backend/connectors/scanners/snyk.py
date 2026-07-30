"""Snyk connector — test connection via REST API."""
import httpx
import logging
from typing import Any, Dict, List
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult

logger = logging.getLogger(__name__)


class SnykConnector(BaseConnector):

    async def test_connection(self) -> ConnectorTestResult:
        api_key = self.credentials.get("api_key", "")
        org_id = self.credentials.get("org_id", "") or self.config.get("org_id", "")
        if not api_key:
            return ConnectorTestResult(success=False, message="Snyk requires 'api_key' in credentials")
        if not org_id:
            return ConnectorTestResult(success=False, message="Snyk requires 'org_id' in credentials or config")
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"https://api.snyk.io/v1/org/{org_id}",
                    headers={"Authorization": f"token {api_key}"},
                )
                if resp.status_code == 401:
                    return ConnectorTestResult(success=False, message="Authentication failed — check API key")
                if resp.status_code == 404:
                    return ConnectorTestResult(success=False, message=f"Organization '{org_id}' not found — check org_id")
                if resp.status_code == 200:
                    data = resp.json()
                    return ConnectorTestResult(
                        success=True,
                        message=f"Connected to Snyk organisation '{data.get('name', org_id)}'",
                        details={"org_id": org_id, "org_name": data.get("name")},
                    )
                return ConnectorTestResult(success=False, message=f"Snyk API returned HTTP {resp.status_code}")
        except httpx.ConnectError as exc:
            return ConnectorTestResult(success=False, message=f"Cannot reach Snyk API — {exc}")
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
