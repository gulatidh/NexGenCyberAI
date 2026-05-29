"""OWASP Dependency-Check — SCA / CVE matching on project dependencies."""
from connectors.scanners.base import WorkflowConnector


class OwaspDependencyCheckConnector(WorkflowConnector):
    WORKFLOW_FILE = "owasp-dc-scan.yml"
    REQUIRED_CONFIG = ["repo_url"]
    RESOURCE_TYPE = "repo"
    DEFAULT_DISPLAY_NAME = "OWASP Dependency-Check"
