"""Qualys VMDR connector — test connection + asset discovery."""
import httpx
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult

logger = logging.getLogger(__name__)

_HEADERS = {
    "X-Requested-With": "NexGenCyberAI",
    "Content-Type": "application/x-www-form-urlencoded",
}


class QualysConnector(BaseConnector):

    async def test_connection(self) -> ConnectorTestResult:
        api_url = self.credentials.get("api_url", "").rstrip("/")
        username = self.credentials.get("username", "")
        password = self.credentials.get("password", "")

        if not api_url:
            return ConnectorTestResult(success=False, message="API URL is required (e.g. https://qualysapi.qg3.apps.qualys.com)")
        if not username or not password:
            return ConnectorTestResult(success=False, message="Username and password are required")

        try:
            async with httpx.AsyncClient(timeout=30, verify=True) as client:
                # Use scan/list as the auth probe — universally accessible on all
                # Qualys subscriptions (unlike user/list which needs admin access)
                resp = await client.post(
                    f"{api_url}/api/2.0/fo/scan/",
                    auth=(username, password),
                    headers=_HEADERS,
                    data={"action": "list"},
                )

                if resp.status_code == 401:
                    return ConnectorTestResult(success=False, message="Authentication failed — check username and password")
                if resp.status_code == 403:
                    return ConnectorTestResult(success=False, message="Access denied — account may lack API access permissions")
                if resp.status_code not in (200, 201):
                    return ConnectorTestResult(success=False, message=f"Qualys API returned HTTP {resp.status_code}")

                # Parse scan count from response
                scan_count = 0
                try:
                    root = ET.fromstring(resp.text)
                    scan_count = len(root.findall(".//SCAN"))
                except ET.ParseError:
                    if "Invalid credentials" in resp.text or "authentication" in resp.text.lower():
                        return ConnectorTestResult(success=False, message="Authentication failed")

                details: Dict[str, Any] = {
                    "platform": api_url,
                    "scan_history_count": scan_count,
                }

                # Check scoped host count (best-effort, non-blocking)
                try:
                    hosts_resp = await client.post(
                        f"{api_url}/api/2.0/fo/asset/host/",
                        auth=(username, password),
                        headers=_HEADERS,
                        data={"action": "list", "truncation_limit": "1"},
                    )
                    if hosts_resp.status_code == 200:
                        hroot = ET.fromstring(hosts_resp.text)
                        hosts = hroot.findall(".//HOST")
                        details["scoped_hosts"] = len(hosts)
                        if len(hosts) == 0:
                            details["note"] = "No hosts in scope yet — import mode will return 0 findings until hosts are added to a Qualys asset group"
                except Exception:
                    pass

                return ConnectorTestResult(
                    success=True,
                    message=f"Connected to Qualys VMDR at {api_url}",
                    details=details,
                )

        except httpx.ConnectError as exc:
            return ConnectorTestResult(
                success=False,
                message=f"Cannot reach Qualys API — check the API URL and network connectivity. Detail: {exc}",
            )
        except httpx.TimeoutException:
            return ConnectorTestResult(
                success=False,
                message="Connection timed out — Qualys API did not respond within 30 seconds",
            )
        except Exception as exc:
            logger.error("Qualys test_connection error: %s", exc, exc_info=True)
            return ConnectorTestResult(success=False, message=f"Unexpected error: {exc}")

    async def get_resources(self) -> List[Dict[str, Any]]:
        api_url = self.credentials.get("api_url", "").rstrip("/")
        username = self.credentials.get("username", "")
        password = self.credentials.get("password", "")
        if not all([api_url, username, password]):
            return []
        try:
            async with httpx.AsyncClient(timeout=60, verify=True) as client:
                resp = await client.post(
                    f"{api_url}/api/2.0/fo/asset/host/",
                    auth=(username, password),
                    headers=_HEADERS,
                    data={"action": "list", "truncation_limit": "500"},
                )
                resp.raise_for_status()
                root = ET.fromstring(resp.text)
                resources = []
                for host in root.findall(".//HOST"):
                    ip = (host.findtext("IP") or "").strip()
                    dns = (host.findtext("DNS") or "").strip()
                    os_name = (host.findtext("OS") or "").strip()
                    if ip:
                        resources.append({
                            "id": ip,
                            "name": dns or ip,
                            "type": "host",
                            "asset_class": "host",
                            "os": os_name,
                            "ip": ip,
                        })
                return resources
        except Exception as exc:
            logger.warning("Qualys get_resources failed: %s", exc)
            return []

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        return []

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
