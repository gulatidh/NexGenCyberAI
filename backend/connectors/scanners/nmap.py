"""NMAP network discovery + service scan."""
from connectors.scanners.base import WorkflowConnector


class NmapConnector(WorkflowConnector):
    WORKFLOW_FILE = "nmap-scan.yml"
    REQUIRED_CONFIG = ["target"]  # host, IP, or CIDR (e.g. 10.0.0.0/24)
    RESOURCE_TYPE = "host"
    DEFAULT_DISPLAY_NAME = "NMAP (Network)"
