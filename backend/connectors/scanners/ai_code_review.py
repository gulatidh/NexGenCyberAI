"""AI Code Review connector — local LLM-powered vulnerability analysis.

Unlike other scanners, this connector does NOT dispatch a GitHub Actions
workflow. Execution happens directly in a FastAPI BackgroundTask via
services.code_review.runner. The connector class exists only to:
  1. Store configuration (repo_url, git credentials)
  2. Satisfy the factory / test_connection contract
  3. Report the target to the inventory
"""
from __future__ import annotations
import re
from typing import Any, Dict, List

from connectors.base import (
    BaseConnector, ConnectorFinding, ConnectorTestResult,
)

_URL_RE = re.compile(r"^https?://\S+|^git@\S+:\S+", re.IGNORECASE)


class AICodeReviewConnector(BaseConnector):

    def _get(self, key: str) -> str:
        for src in (self.config or {}, self.credentials or {}):
            v = src.get(key)
            if v:
                return str(v)
        return ""

    async def test_connection(self) -> ConnectorTestResult:
        repo_url = self._get("repo_url")

        if not repo_url:
            # Archive-upload mode — no repo URL needed; valid configuration.
            return ConnectorTestResult(
                success=True,
                message="Configured for archive-upload mode. Upload a .zip or .tar.gz archive when starting a scan.",
                details={"mode": "archive"},
            )

        if not _URL_RE.match(repo_url):
            return ConnectorTestResult(
                success=False,
                message=f"Invalid repo URL '{repo_url}' — must start with https:// or git@",
                details={"repo_url": repo_url},
            )

        # For public repos we can do a lightweight reachability check via
        # git ls-remote without cloning. For private repos with a token we
        # skip the network check and trust the credential is correct.
        git_token = self._get("git_token")
        if not git_token:
            import subprocess
            try:
                result = subprocess.run(
                    ["git", "ls-remote", "--exit-code", "--heads", repo_url],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0:
                    return ConnectorTestResult(
                        success=True,
                        message=f"Repository reachable: {repo_url}",
                        details={"repo_url": repo_url, "mode": "git_clone"},
                    )
                return ConnectorTestResult(
                    success=False,
                    message=f"Repository not reachable (exit {result.returncode}). Check the URL or add git credentials for private repos.",
                    details={"repo_url": repo_url, "stderr": result.stderr[:300]},
                )
            except subprocess.TimeoutExpired:
                return ConnectorTestResult(
                    success=False,
                    message="Timeout reaching repository — check network connectivity.",
                    details={"repo_url": repo_url},
                )
            except FileNotFoundError:
                # git not in PATH on this host — skip the check
                pass

        # Private repo or git not available — accept on configuration alone
        return ConnectorTestResult(
            success=True,
            message=f"Configured for {repo_url} — credentials will be used at scan time.",
            details={"repo_url": repo_url, "mode": "git_clone_authenticated"},
        )

    async def get_resources(self) -> List[Dict[str, Any]]:
        repo_url = self._get("repo_url")
        if not repo_url:
            return []
        return [{"id": repo_url, "name": repo_url, "type": "code_repository"}]

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        # Execution is handled by services.code_review.runner, not here.
        return []

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
