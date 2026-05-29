"""Gitleaks — secret scanner for git history."""
from connectors.scanners.base import WorkflowConnector


class GitleaksConnector(WorkflowConnector):
    WORKFLOW_FILE = "gitleaks-scan.yml"
    REQUIRED_CONFIG = ["repo_url"]
    RESOURCE_TYPE = "repo"
    DEFAULT_DISPLAY_NAME = "Gitleaks"
