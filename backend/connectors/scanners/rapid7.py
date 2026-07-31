"""Rapid7 InsightVM connector — test connection via REST API.

Two deployment modes auto-detected from host:
  Cloud   host contains 'insight.rapid7.com' → us.api.insight.rapid7.com, API key
  On-prem any other host:port               → Basic Auth or API key, /api/3/

Auth (both modes):
  api_key   → X-Api-Key header  (recommended — no MFA)
  username + password → HTTP Basic Auth (may trigger MFA)
"""
import httpx
import logging
from typing import Any, Dict, List
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult

logger = logging.getLogger(__name__)

_CLOUD_BASE = "https://us.api.insight.rapid7.com"


def _is_cloud(host: str) -> bool:
    return "insight.rapid7.com" in host


def _auth_kwargs(creds: dict) -> dict:
    api_key = creds.get("api_key", "").strip()
    if api_key:
        return {"headers": {"X-Api-Key": api_key, "Content-Type": "application/json"}}
    return {"auth": (creds.get("username", ""), creds.get("password", ""))}


class Rapid7Connector(BaseConnector):

    async def test_connection(self) -> ConnectorTestResult:
        host = self.credentials.get("host", "").rstrip("/")
        api_key = self.credentials.get("api_key", "").strip()
        username = self.credentials.get("username", "")
        password = self.credentials.get("password", "")
        port = self.config.get("port", 3780)

        if not host:
            return ConnectorTestResult(success=False, message="Rapid7 requires 'host' (e.g. insight.rapid7.com for cloud, or your on-prem IP)")
        if not api_key and not (username and password):
            return ConnectorTestResult(
                success=False,
                message="Provide 'api_key' (recommended — no MFA) or 'username' + 'password'",
            )

        cloud = _is_cloud(host)
        auth_mode = "API Key" if api_key else "Basic Auth"

        try:
            async with httpx.AsyncClient(verify=False, timeout=20) as client:
                if cloud:
                    # InsightVM Cloud — POST to integration/assets
                    resp = await client.post(
                        f"{_CLOUD_BASE}/vm/v4/integration/assets",
                        content=b'{"size":1}',
                        **_auth_kwargs(self.credentials),
                    )
                    if resp.status_code == 401:
                        return ConnectorTestResult(success=False, message="API key rejected — check Insight Platform API key")
                    if resp.status_code == 200:
                        meta = resp.json().get("metadata", {})
                        asset_count = meta.get("totalResources", 0)
                        return ConnectorTestResult(
                            success=True,
                            message=f"Connected to Rapid7 InsightVM Cloud via {auth_mode}",
                            details={
                                "mode": "cloud",
                                "auth_mode": auth_mode,
                                "assets": asset_count,
                                "note": "Connect assets in Insight platform to populate findings" if asset_count == 0 else f"{asset_count} assets discovered",
                            },
                        )
                    return ConnectorTestResult(success=False, message=f"Rapid7 Cloud API returned HTTP {resp.status_code}")
                else:
                    # On-prem InsightVM
                    resp = await client.get(
                        f"{host}:{port}/api/3/administration/info",
                        **_auth_kwargs(self.credentials),
                    )
                    if resp.status_code == 401:
                        msg = "API key rejected" if api_key else "Authentication failed — check credentials (MFA may be blocking API access)"
                        return ConnectorTestResult(success=False, message=msg)
                    if resp.status_code == 200:
                        data = resp.json()
                        return ConnectorTestResult(
                            success=True,
                            message=f"Connected to Rapid7 InsightVM on-prem at {host}:{port} via {auth_mode}",
                            details={"mode": "on-prem", "version": data.get("version", "unknown"), "auth_mode": auth_mode},
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
