"""Checkov — Bridgecrew/Prisma Cloud IaC security scanner.

Dispatches a GitHub Actions workflow (checkov-scan.yml) that installs
Checkov, clones the target Git repository, and runs a comprehensive
infrastructure-as-code policy scan across Terraform, CloudFormation,
Kubernetes, Helm, Dockerfiles, GitHub Actions, ARM, Bicep, and Ansible.

Checkov checks ~1000+ policies mapped to CIS, NIST 800-53, SOC 2,
PCI-DSS, GDPR, and CIS Benchmarks.  Findings are ingested via the
/scans/ingest/ callback once the workflow completes.
"""
from connectors.scanners.base import WorkflowConnector


class CheckovConnector(WorkflowConnector):
    WORKFLOW_FILE = "checkov-scan.yml"
    REQUIRED_CONFIG = ["repo_url"]
    RESOURCE_TYPE = "iac-repo"
    DEFAULT_DISPLAY_NAME = "Checkov (IaC)"
