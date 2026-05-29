"""GitHub CodeQL SAST connector — runs via GitHub Actions."""
from connectors.scanners.base import WorkflowConnector


class CodeQLConnector(WorkflowConnector):
    WORKFLOW_FILE = "codeql-scan.yml"
    REQUIRED_CONFIG = ["repo_url"]
    RESOURCE_TYPE = "repo"
    DEFAULT_DISPLAY_NAME = "GitHub CodeQL (SAST)"
