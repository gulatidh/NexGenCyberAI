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
                # Auth probe: VM Detection API — same endpoint the scanner uses,
                # confirmed working for this account/platform in prior testing.
                # truncation_limit=1 returns at most 1 host record (minimal data).
                resp = await client.post(
                    f"{api_url}/api/4.0/fo/asset/host/vm/detection/",
                    auth=(username, password),
                    headers=_HEADERS,
                    data={
                        "action": "list",
                        "output_format": "XML",
                        "truncation_limit": "1",
                    },
                )

                if resp.status_code == 401:
                    return ConnectorTestResult(success=False, message="Authentication failed — check username and password")
                if resp.status_code == 403:
                    return ConnectorTestResult(success=False, message="Access denied — account may lack VMDR API permissions")
                if resp.status_code not in (200, 201):
                    return ConnectorTestResult(success=False, message=f"Qualys API returned HTTP {resp.status_code}")

                # Qualys returns HTTP 200 even for auth/routing errors — parse XML body
                host_count = 0
                try:
                    root = ET.fromstring(resp.text)
                    # Check for Qualys error response (CODE + TEXT inside SIMPLE_RETURN)
                    err_text = root.findtext(".//TEXT") or ""
                    err_code = root.findtext(".//CODE") or ""
                    if err_text and not root.findall(".//HOST"):
                        # "not authenticated to url" means wrong API URL (qualysguard vs qualysapi)
                        if "not authenticated" in err_text.lower():
                            return ConnectorTestResult(
                                success=False,
                                message=f"Wrong API URL — use qualysapi.qg3.apps.qualys.com not qualysguard. Qualys error: {err_text}",
                            )
                        if err_code in ("999", "1000") or "authentication" in err_text.lower() or "invalid" in err_text.lower():
                            return ConnectorTestResult(success=False, message=f"Qualys rejected credentials: {err_text}")
                    host_count = len(root.findall(".//HOST"))
                except ET.ParseError:
                    if "Invalid credentials" in resp.text or "authentication" in resp.text.lower():
                        return ConnectorTestResult(success=False, message="Authentication failed")

                details: Dict[str, Any] = {
                    "platform": api_url,
                    "hosts_with_detections": host_count,
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
                            details["note"] = "No hosts in scope — import scan will return 0 findings until hosts are scanned in Qualys"
                except Exception:
                    pass

                # Best-effort TotalCloud probe — detect if CSPM module is available
                try:
                    tc_resp = await client.post(
                        f"{api_url}/cloudview-api/rest/v1/failures",
                        auth=(username, password),
                        headers={"X-Requested-With": "NexGenCyberAI", "Content-Type": "application/json", "Accept": "application/json"},
                        json={"filter": "cloudType:AZURE", "pageNo": 0, "pageSize": 1},
                        timeout=15,
                    )
                    if tc_resp.status_code == 200:
                        details["totalcloud_cspm"] = True
                        details["note"] = "VMDR + TotalCloud CSPM enabled — scans will include Azure cloud posture findings"
                    else:
                        details["totalcloud_cspm"] = False
                except Exception:
                    details["totalcloud_cspm"] = False

                return ConnectorTestResult(
                    success=True,
                    message=f"Connected to Qualys {'VMDR + TotalCloud CSPM' if details.get('totalcloud_cspm') else 'VMDR'} at {api_url}",
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
