"""Web (OWASP ZAP) connector — runs scans on a remote runner.

The actual ZAP scan executes in a GitHub Actions workflow (cheap, no
infra to maintain). When a scan is initiated:

  1. Backend records the Scan row (status=running).
  2. `run_configuration_review()` does the form/oauth pre-login if
     applicable, then triggers the workflow_dispatch.
  3. The workflow fetches the target URL + prepared auth headers via
     `GET /scans/config/?scan_id=...&scan_token=...`.
  4. ZAP runs (baseline or active) and posts findings to
     `POST /scans/ingest/` with the same scan_token.
  5. Ingest endpoint marks the scan completed.

Because the actual scanning happens out of band, `run_configuration_review`
returns an empty list — findings are persisted later via the ingest path.
"""
from __future__ import annotations
import logging
import os
from typing import Any, Dict, List, Optional

import httpx

from connectors.base import (
    BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity,
)
from connectors.web.auth import prepare_auth_headers

logger = logging.getLogger(__name__)

WORKFLOW_FILE = "zap-scan.yml"


class WebConnector(BaseConnector):
    """OWASP ZAP runner with auth + non-auth modes.

    `credentials` schema (encrypted at rest by the connectors router):
      {
        "auth": {
          "method": "none" | "bearer" | "cookie" | "form" | "oauth_client_credentials",
          ...method-specific fields (token, login_url, username, password, ...)
        }
      }
    `config` schema:
      {
        "target_url": "https://app.example.com",
        "exclude_paths": ["/logout", "/payment"],   # optional
        "default_profile": "baseline" | "active",   # default baseline
      }
    """

    def __init__(self, credentials: Dict[str, Any], config: Dict[str, Any]):
        super().__init__(credentials, config)
        self.target_url: str = (config or {}).get("target_url", "").rstrip("/")
        self.auth: Dict[str, Any] = (credentials or {}).get("auth", {"method": "none"})

    async def test_connection(self) -> ConnectorTestResult:
        if not self.target_url:
            return ConnectorTestResult(success=False, message="target_url is required")
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                resp = await client.head(self.target_url)
                # Some sites reject HEAD — retry GET
                if resp.status_code >= 400:
                    resp = await client.get(self.target_url)
            return ConnectorTestResult(
                success=resp.status_code < 500,
                message=f"Reachable (HTTP {resp.status_code})",
                details={"status_code": resp.status_code},
            )
        except Exception as exc:
            return ConnectorTestResult(success=False, message=f"Unreachable: {exc}")

    async def get_resources(self) -> List[Dict[str, Any]]:
        """Web target is a single 'resource' from the inventory POV."""
        if not self.target_url:
            return []
        return [{
            "id": self.target_url,
            "name": self.target_url,
            "type": "web/application",
            "asset_class": "web",
        }]

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        """No findings emitted directly — workflow ingests them later.

        The scans router calls `trigger_zap_scan(...)` separately; this
        method exists only to satisfy the BaseConnector contract.
        """
        return []

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {"framework": framework, "controls": []}


def trigger_zap_scan(
    scan_id: str,
    target_url: str,
    auth: Dict[str, Any],
    profile: str = "baseline",
    exclude_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Pre-login (if needed) + dispatch the GitHub workflow.

    Returns a dict with the dispatch outcome. Caller (scans router) sets
    Scan.status=running and waits for the ingest callback.
    """
    from core.scan_tokens import mint_scan_token
    from core.github_dispatch import dispatch_workflow

    # Run form/oauth pre-login synchronously so the workflow gets
    # a ready-to-inject Authorization or Cookie header.
    prepared_headers = prepare_auth_headers(auth)
    auth_used = (auth or {}).get("method", "none")

    # The token authenticates the workflow's callback to the API.
    scan_token = mint_scan_token(scan_id)

    # Workflow inputs are visible in the GitHub run UI; keep secrets out
    # of them. The workflow fetches the prepared headers via /scans/config/.
    inputs = {
        "scan_id": scan_id,
        "scan_token": scan_token,
        "api_base": (os.environ.get("PUBLIC_API_BASE") or "").rstrip("/"),
        "target_url": target_url,
        "profile": profile or "baseline",
    }

    # Persist the prepared headers + excludes for the runner to fetch.
    from services.scan_runtime import set_runtime
    set_runtime(scan_id, {
        "target_url": target_url,
        "profile": profile or "baseline",
        "auth_headers": prepared_headers,
        "exclude_paths": exclude_paths or [],
        "auth_method": auth_used,
    })

    return dispatch_workflow(WORKFLOW_FILE, inputs)
