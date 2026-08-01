"""SSLyze — TLS/SSL configuration analysis scanner.

Dispatches a GitHub Actions workflow (sslyze-scan.yml) that installs SSLyze
and runs a comprehensive TLS/SSL assessment against the target host:port.

Checks performed:
  - Protocol support: SSL 2.0, SSL 3.0, TLS 1.0/1.1/1.2/1.3
  - Known vulnerabilities: Heartbleed, ROBOT, CRIME/BREACH (TLS compression)
  - TLS Fallback SCSV support
  - Weak cipher suites: RC4, 3DES, EXPORT, NULL, anonymous
  - Certificate validity: expiry, hostname match, chain trust, self-signed

Findings are ingested via the /scans/ingest/ callback once the workflow
completes.
"""
from connectors.scanners.base import WorkflowConnector


class SSLyzeConnector(WorkflowConnector):
    WORKFLOW_FILE = "sslyze-scan.yml"
    REQUIRED_CONFIG = ["target"]   # hostname or hostname:port
    RESOURCE_TYPE = "network/tls"
    DEFAULT_DISPLAY_NAME = "SSLyze (TLS/SSL)"
