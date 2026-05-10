"""Trigger GitHub Actions workflows via workflow_dispatch.

Used by the web (ZAP) connector to start a remote scan. The PAT used
must have `actions:write` on the target repo (a fine-grained PAT scoped
to the repo is fine, or a GitHub App installation token).

Env required:
  GITHUB_DISPATCH_TOKEN   PAT or App token with actions:write
  GITHUB_REPO_OWNER       e.g. "gulatidh"
  GITHUB_REPO_NAME        e.g. "NexGenCyberAI"
  GITHUB_WORKFLOW_REF     branch / tag the workflow lives on (default: "main")
"""
from __future__ import annotations
import logging
import os
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)


def dispatch_workflow(workflow_file: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
    """POST /repos/{owner}/{repo}/actions/workflows/{file}/dispatches.

    Returns {"ok": True} on success, {"ok": False, "error": "..."} otherwise.
    Does not raise — caller decides whether to fail the scan.
    """
    token = os.environ.get("GITHUB_DISPATCH_TOKEN")
    owner = os.environ.get("GITHUB_REPO_OWNER")
    repo = os.environ.get("GITHUB_REPO_NAME")
    ref = os.environ.get("GITHUB_WORKFLOW_REF", "main")

    if not (token and owner and repo):
        logger.warning("GitHub dispatch env not configured — skipping")
        return {"ok": False, "error": "GitHub dispatch not configured"}

    url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_file}/dispatches"
    payload = {"ref": ref, "inputs": {k: str(v) for k, v in inputs.items() if v is not None}}
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        resp = httpx.post(url, json=payload, headers=headers, timeout=15)
        if resp.status_code == 204:
            return {"ok": True, "ref": ref}
        return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
