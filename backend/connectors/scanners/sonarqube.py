"""SonarQube SAST connector — supports Community (self-hosted) and
Enterprise (via SonarCloud / GitHub Action) deployments."""
from connectors.scanners.base import WorkflowConnector


class SonarQubeConnector(WorkflowConnector):
    WORKFLOW_FILE = "sonarqube-scan.yml"
    # Either point at a self-hosted Sonar server with a repo to analyze,
    # or supply just a sonar_token + project_key for SonarCloud.
    REQUIRED_CONFIG = ["repo_url", "sonar_host_url", "sonar_project_key"]
    RESOURCE_TYPE = "repo"
    DEFAULT_DISPLAY_NAME = "SonarQube (SAST)"

    def _primary_target(self) -> str:
        # SonarQube can be referenced by either repo or project_key
        for key in ["repo_url", "sonar_project_key", "sonar_host_url"]:
            val = (self.config or {}).get(key)
            if val:
                return str(val)
        return ""
