"""Trivy — container image + filesystem + IaC scanner."""
from connectors.scanners.base import WorkflowConnector


class TrivyConnector(WorkflowConnector):
    WORKFLOW_FILE = "trivy-scan.yml"
    # Either scan a container image OR a git repo for IaC/dependency issues.
    REQUIRED_CONFIG = ["image", "repo_url"]
    RESOURCE_TYPE = "container"
    DEFAULT_DISPLAY_NAME = "Trivy"
