"""TruffleHog — secret scanner (git history + filesystem + S3 + more)."""
from connectors.scanners.base import WorkflowConnector


class TruffleHogConnector(WorkflowConnector):
    WORKFLOW_FILE = "trufflehog-scan.yml"
    REQUIRED_CONFIG = ["repo_url"]
    RESOURCE_TYPE = "repo"
    DEFAULT_DISPLAY_NAME = "TruffleHog"
