"""OpenVAS / Greenbone vulnerability scanner."""
from connectors.scanners.base import WorkflowConnector


class OpenVASConnector(WorkflowConnector):
    WORKFLOW_FILE = "openvas-scan.yml"
    REQUIRED_CONFIG = ["target"]  # host or CIDR
    RESOURCE_TYPE = "host"
    DEFAULT_DISPLAY_NAME = "OpenVAS / Greenbone"
