"""Semgrep SAST connector — runs via GitHub Actions."""
from connectors.scanners.base import WorkflowConnector


class SemgrepConnector(WorkflowConnector):
    WORKFLOW_FILE = "semgrep-scan.yml"
    REQUIRED_CONFIG = ["repo_url"]
    RESOURCE_TYPE = "repo"
    DEFAULT_DISPLAY_NAME = "Semgrep (SAST)"
