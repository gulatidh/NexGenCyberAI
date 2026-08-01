"""Nuclei — ProjectDiscovery's fast vulnerability scanner.

Dispatches a GitHub Actions workflow (nuclei-scan.yml) that downloads the
Nuclei binary, updates templates, and runs a broad scan across network,
HTTP, SSL, default-login, misconfiguration, and CVE template categories.

Findings are ingested via the /scans/ingest/ callback once the workflow
completes.  This connector is categorised as DAST because Nuclei's primary
strength is active HTTP/web scanning, though it also covers network targets.
"""
from connectors.scanners.base import WorkflowConnector


class NucleiConnector(WorkflowConnector):
    WORKFLOW_FILE = "nuclei-scan.yml"
    # Accept either a URL (target_url) or a bare hostname/IP (target)
    REQUIRED_CONFIG = ["target_url", "target"]
    RESOURCE_TYPE = "host"
    DEFAULT_DISPLAY_NAME = "Nuclei (Web/Network)"
