"""WorkflowConnector — shared base for GitHub-Actions-driven scanners.

Used by Semgrep, CodeQL, SonarQube, NMAP, OpenVAS, Trivy, OWASP DC,
Gitleaks, TruffleHog. Mirrors the WebConnector (ZAP) pattern: the
actual scan runs in CI; the connector here is responsible only for
storing target config, validating it, and surfacing the resource to
the inventory.

Subclasses must set:
  - WORKFLOW_FILE: the .github/workflows/<file>.yml that dispatches
  - REQUIRED_CONFIG: list of config keys the scanner needs
  - RESOURCE_TYPE: short string for the inventory (e.g. "repo", "host")
  - DEFAULT_DISPLAY_NAME: fallback name shown to humans
"""
from __future__ import annotations
from typing import Any, ClassVar, Dict, List

from connectors.base import (
    BaseConnector, ConnectorFinding, ConnectorTestResult,
)


class WorkflowConnector(BaseConnector):
    """Async scanner that defers execution to a GitHub Actions workflow.

    `config` schema:
      One of REQUIRED_CONFIG keys must be set. Typical:
        - repo_url:   git URL (SAST + dependency + secret scanners)
        - target:     host / IP / network range (NMAP, OpenVAS)
        - image:      container image ref (Trivy)
        - target_url: URL (web-style scanners)
    """

    WORKFLOW_FILE: ClassVar[str] = ""
    REQUIRED_CONFIG: ClassVar[List[str]] = []
    RESOURCE_TYPE: ClassVar[str] = "scan-target"
    DEFAULT_DISPLAY_NAME: ClassVar[str] = "Scan target"

    def __init__(self, credentials: Dict[str, Any], config: Dict[str, Any]):
        super().__init__(credentials, config)

    def _get(self, key: str) -> str:
        """Pull a value by key from either `config` (non-secret) or
        `credentials` (where the standard credential form puts everything).

        The Connectors UI doesn't have a config/credentials split for these
        scanners, so target URLs / image refs / project keys land under
        `credentials` even though they aren't secret. Read from both so the
        scanner works regardless of which side the field was saved on.
        """
        for source in (self.config or {}, self.credentials or {}):
            v = source.get(key)
            if v:
                return str(v)
        return ""

    def _primary_target(self) -> str:
        """Return whichever required config key is populated (the 'target')."""
        for key in self.REQUIRED_CONFIG:
            v = self._get(key)
            if v:
                return v
        return ""

    async def test_connection(self) -> ConnectorTestResult:
        target = self._primary_target()
        if not target:
            return ConnectorTestResult(
                success=False,
                message=f"Missing required config — need one of: {', '.join(self.REQUIRED_CONFIG)}",
            )
        # Workflow-driven connectors can't really "test" without running CI.
        # Just confirm config is well-formed.
        return ConnectorTestResult(
            success=True,
            message=f"Configured for {target} — scan runs via GitHub Actions ({self.WORKFLOW_FILE})",
            details={"target": target, "workflow": self.WORKFLOW_FILE},
        )

    async def get_resources(self) -> List[Dict[str, Any]]:
        target = self._primary_target()
        if not target:
            return []
        return [{
            "id": target,
            "name": target,
            "type": f"{self.RESOURCE_TYPE}/{self.WORKFLOW_FILE.replace('.yml', '')}",
            "asset_class": self.RESOURCE_TYPE,
        }]

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        # Findings arrive via the /scans/ingest/ callback once the workflow finishes.
        return []

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
