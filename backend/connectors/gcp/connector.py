"""
NexGenCyberAI - GCP Connector
Uses google-cloud-securitycenter and google-cloud-asset APIs.
Auth via Service Account JSON key or Workload Identity.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List
from google.cloud import securitycenter_v1, asset_v1
from google.oauth2 import service_account
import json

from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
}

# Risky GCP firewall ports: port → (service name, severity)
RISKY_PORTS_GCP: Dict[int, tuple] = {
    22:   ("SSH",        FindingSeverity.HIGH),
    3389: ("RDP",        FindingSeverity.CRITICAL),
    3306: ("MySQL",      FindingSeverity.HIGH),
    5432: ("PostgreSQL", FindingSeverity.HIGH),
    6379: ("Redis",      FindingSeverity.HIGH),
}

# Age threshold for service account key rotation
SA_KEY_MAX_AGE_DAYS = 90


class GCPConnector(BaseConnector):

    def _credentials(self):
        if sa_json := self.credentials.get("service_account_json"):
            info = json.loads(sa_json) if isinstance(sa_json, str) else sa_json
            return service_account.Credentials.from_service_account_info(
                info,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
        return None  # use ADC

    async def test_connection(self) -> ConnectorTestResult:
        try:
            creds = self._credentials()
            project_id = self.credentials["project_id"]
            client = asset_v1.AssetServiceClient(credentials=creds)
            parent = f"projects/{project_id}"
            resp = client.list_assets(request={"parent": parent, "page_size": 1})
            return ConnectorTestResult(
                success=True,
                message=f"Connected to GCP project {project_id}",
                details={"project_id": project_id},
            )
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    async def get_resources(self) -> List[Dict[str, Any]]:
        creds = self._credentials()
        project_id = self.credentials["project_id"]
        client = asset_v1.AssetServiceClient(credentials=creds)
        resources = []
        request = asset_v1.ListAssetsRequest(
            parent=f"projects/{project_id}",
            asset_types=["compute.googleapis.com/Instance", "storage.googleapis.com/Bucket"],
            content_type=asset_v1.ContentType.RESOURCE,
        )
        for asset in client.list_assets(request=request):
            resources.append({
                "id": asset.name,
                "name": asset.name.split("/")[-1],
                "type": asset.asset_type,
                "project": project_id,
            })
        return resources

    # ── GCS Buckets ───────────────────────────────────────────────────────────

    def _check_gcs_buckets(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from google.cloud import storage
            creds = self._credentials()
            project_id = self.credentials["project_id"]
            client = storage.Client(credentials=creds, project=project_id)

            for bucket in client.list_buckets():
                name = bucket.name
                bucket_resource_id = f"//storage.googleapis.com/projects/_/buckets/{name}"

                # Check IAM policy for public access
                try:
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    for binding in policy.bindings:
                        members = binding.get("members", [])
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            findings.append(ConnectorFinding(
                                title=f"GCS bucket '{name}' is publicly accessible",
                                description=(
                                    f"The IAM policy for GCS bucket '{name}' grants access to "
                                    f"'allUsers' or 'allAuthenticatedUsers'. Any internet user can access this bucket."
                                ),
                                severity=FindingSeverity.CRITICAL,
                                resource_id=bucket_resource_id,
                                resource_type="storage.googleapis.com/Bucket",
                                control_id="NIST AC-3",
                                framework="nist",
                                remediation=(
                                    f"Remove 'allUsers' and 'allAuthenticatedUsers' from the IAM bindings "
                                    f"of bucket '{name}' and enable uniform bucket-level access."
                                ),
                            ))
                            break
                except Exception as exc:
                    logger.warning("GCS IAM policy check failed for bucket '%s': %s", name, exc)

                # Check uniform bucket-level access
                try:
                    bucket.reload()
                    iam_config = bucket.iam_configuration
                    if not getattr(iam_config, "uniform_bucket_level_access_enabled", False):
                        findings.append(ConnectorFinding(
                            title=f"GCS bucket '{name}' has uniform bucket-level access disabled (legacy ACLs active)",
                            description=(
                                f"Uniform bucket-level access is not enabled on bucket '{name}'. "
                                f"Legacy object ACLs are active, which can lead to inconsistent access controls "
                                f"that are harder to audit and manage."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            resource_id=bucket_resource_id,
                            resource_type="storage.googleapis.com/Bucket",
                            control_id="NIST SC-28",
                            framework="nist",
                            remediation=(
                                f"Enable uniform bucket-level access on bucket '{name}' to enforce "
                                f"IAM-only access control and disable legacy object ACLs."
                            ),
                        ))
                except Exception as exc:
                    logger.warning("GCS uniform access check failed for bucket '%s': %s", name, exc)

                # Check versioning
                try:
                    if not bucket.versioning_enabled:
                        findings.append(ConnectorFinding(
                            title=f"GCS bucket '{name}' has versioning disabled",
                            description=(
                                f"Object versioning is not enabled on GCS bucket '{name}'. "
                                f"Accidental deletions or overwrites cannot be recovered."
                            ),
                            severity=FindingSeverity.LOW,
                            resource_id=bucket_resource_id,
                            resource_type="storage.googleapis.com/Bucket",
                            control_id="NIST SC-28",
                            framework="nist",
                            remediation=f"Enable object versioning on GCS bucket '{name}'.",
                        ))
                except Exception as exc:
                    logger.warning("GCS versioning check failed for bucket '%s': %s", name, exc)

        except ImportError:
            logger.warning("google-cloud-storage not installed; skipping GCS bucket checks")
        except Exception as exc:
            logger.warning("GCS bucket scan failed: %s", exc)
        return findings

    # ── Compute Firewall Rules ────────────────────────────────────────────────

    def _check_compute_firewall_rules(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from google.cloud import compute_v1
            creds = self._credentials()
            project_id = self.credentials["project_id"]
            fw_client = compute_v1.FirewallsClient(credentials=creds)

            for rule in fw_client.list(project=project_id):
                rule_name = rule.name
                resource_id = f"//compute.googleapis.com/projects/{project_id}/global/firewalls/{rule_name}"

                # Only inspect inbound rules
                if rule.direction != "INGRESS":
                    continue

                # Check if source ranges include 0.0.0.0/0 or ::/0
                source_ranges = list(rule.source_ranges or [])
                open_to_internet = "0.0.0.0/0" in source_ranges or "::/0" in source_ranges
                if not open_to_internet:
                    continue

                # Check allowed protocols/ports
                for allowed in rule.allowed:
                    ip_protocol = allowed.ip_protocol or ""
                    ports = list(allowed.ports or [])

                    # Allow-all rule
                    if ip_protocol == "all" or (not ports and ip_protocol in ("tcp", "udp")):
                        if ip_protocol == "all":
                            findings.append(ConnectorFinding(
                                title=f"GCP firewall rule '{rule_name}' allows all inbound traffic from internet",
                                description=(
                                    f"Firewall rule '{rule_name}' in project '{project_id}' allows all protocols "
                                    f"and ports from 0.0.0.0/0 or ::/0. This exposes every service running "
                                    f"in the associated network to the public internet."
                                ),
                                severity=FindingSeverity.CRITICAL,
                                resource_id=resource_id,
                                resource_type="compute.googleapis.com/Firewall",
                                control_id="NIST SC-7",
                                framework="nist",
                                remediation=(
                                    f"Delete or restrict firewall rule '{rule_name}'. "
                                    f"Define explicit allow rules for specific ports and source IP ranges."
                                ),
                            ))
                            continue

                    # Check risky ports in the port list
                    for port_spec in ports:
                        # Port spec can be "22", "22-25", etc.
                        for port, (svc, sev) in RISKY_PORTS_GCP.items():
                            port_exposed = False
                            if "-" in str(port_spec):
                                try:
                                    lo, hi = port_spec.split("-", 1)
                                    port_exposed = int(lo) <= port <= int(hi)
                                except (ValueError, TypeError):
                                    pass
                            else:
                                try:
                                    port_exposed = int(port_spec) == port
                                except (ValueError, TypeError):
                                    pass
                            if port_exposed:
                                findings.append(ConnectorFinding(
                                    title=f"GCP firewall rule '{rule_name}' allows inbound {svc} (port {port}) from internet",
                                    description=(
                                        f"Firewall rule '{rule_name}' permits inbound {ip_protocol.upper()} "
                                        f"traffic on port {port} ({svc}) from {', '.join(source_ranges)}. "
                                        f"This exposes the service to brute-force and exploitation from the internet."
                                    ),
                                    severity=sev,
                                    resource_id=resource_id,
                                    resource_type="compute.googleapis.com/Firewall",
                                    control_id="NIST SC-7",
                                    framework="nist",
                                    remediation=(
                                        f"Restrict firewall rule '{rule_name}' to allow port {port} only from "
                                        f"known IP ranges. Use Cloud IAP or a VPN for administrative access."
                                    ),
                                ))

        except ImportError:
            logger.warning("google-cloud-compute not installed; skipping GCP firewall rule checks")
        except Exception as exc:
            logger.warning("GCP firewall rule scan failed: %s", exc)
        return findings

    # ── IAM Service Accounts ──────────────────────────────────────────────────

    def _check_iam_service_accounts(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            import googleapiclient.discovery
            creds = self._credentials()
            project_id = self.credentials["project_id"]
            iam_service = googleapiclient.discovery.build("iam", "v1", credentials=creds)

            # List all service accounts
            sa_request = iam_service.projects().serviceAccounts().list(
                name=f"projects/{project_id}"
            )
            response = sa_request.execute()
            service_accounts = response.get("accounts", [])

            cutoff = datetime.now(timezone.utc) - timedelta(days=SA_KEY_MAX_AGE_DAYS)

            for sa in service_accounts:
                sa_email = sa.get("email", "")
                sa_name = sa.get("name", sa_email)
                sa_disabled = sa.get("disabled", False)

                if sa_disabled:
                    continue

                # Check for user-managed keys older than 90 days
                try:
                    keys_resp = iam_service.projects().serviceAccounts().keys().list(
                        name=sa_name,
                        keyTypes=["USER_MANAGED"],
                    ).execute()
                    for key in keys_resp.get("keys", []):
                        valid_after = key.get("validAfterTime", "")
                        if valid_after:
                            try:
                                key_created = datetime.fromisoformat(
                                    valid_after.replace("Z", "+00:00")
                                )
                                if key_created < cutoff:
                                    age_days = (datetime.now(timezone.utc) - key_created).days
                                    findings.append(ConnectorFinding(
                                        title=f"Service account '{sa_email}' has a key older than 90 days — rotate it",
                                        description=(
                                            f"Service account '{sa_email}' has a user-managed key "
                                            f"(ID: {key.get('name', '').split('/')[-1]}) that is {age_days} days old. "
                                            f"Keys older than {SA_KEY_MAX_AGE_DAYS} days increase the risk of "
                                            f"credential exposure from undetected leaks."
                                        ),
                                        severity=FindingSeverity.MEDIUM,
                                        resource_id=sa.get("name", sa_email),
                                        resource_type="iam.googleapis.com/ServiceAccount",
                                        control_id="NIST AC-2",
                                        framework="nist",
                                        remediation=(
                                            f"Rotate the user-managed key for service account '{sa_email}'. "
                                            f"Consider using Workload Identity Federation to eliminate long-lived keys entirely."
                                        ),
                                    ))
                            except (ValueError, TypeError) as exc:
                                logger.warning(
                                    "Could not parse key creation date for SA '%s': %s", sa_email, exc
                                )
                except Exception as exc:
                    logger.warning("Service account key check failed for '%s': %s", sa_email, exc)

                # Flag service accounts with privileged naming
                sa_display = sa_email.lower()
                if "admin" in sa_display or "owner" in sa_display:
                    findings.append(ConnectorFinding(
                        title=f"Service account '{sa_email}' has privileged naming — verify least-privilege",
                        description=(
                            f"Service account '{sa_email}' has 'admin' or 'owner' in its name, "
                            f"suggesting it may hold elevated permissions. "
                            f"Verify that this account follows the principle of least privilege."
                        ),
                        severity=FindingSeverity.LOW,
                        resource_id=sa.get("name", sa_email),
                        resource_type="iam.googleapis.com/ServiceAccount",
                        control_id="NIST AC-6",
                        framework="nist",
                        remediation=(
                            f"Review the IAM roles bound to service account '{sa_email}'. "
                            f"Remove any roles broader than what the workload requires."
                        ),
                    ))

        except ImportError:
            logger.warning(
                "google-api-python-client not installed; skipping GCP service account checks"
            )
        except Exception as exc:
            logger.warning("GCP service account scan failed: %s", exc)
        return findings

    # ── Cloud Logging / Export Sinks ──────────────────────────────────────────

    def _check_cloud_logging(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            from google.cloud import logging_v2
            creds = self._credentials()
            project_id = self.credentials["project_id"]
            log_client = logging_v2.Client(credentials=creds, project=project_id)

            sinks = list(log_client.list_sinks())
            if not sinks:
                findings.append(ConnectorFinding(
                    title="GCP project has no Cloud Logging export sinks configured — audit logs are not exported",
                    description=(
                        f"No Cloud Logging export sinks are configured for project '{project_id}'. "
                        f"Without export sinks, audit logs are retained only in Cloud Logging and are not "
                        f"forwarded to a SIEM, Cloud Storage, or BigQuery for long-term retention and analysis."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    resource_id=f"//cloudresourcemanager.googleapis.com/projects/{project_id}",
                    resource_type="logging.googleapis.com/LogSink",
                    control_id="NIST AU-2",
                    framework="nist",
                    remediation=(
                        f"Create a Cloud Logging export sink for project '{project_id}' "
                        f"to forward audit logs to Cloud Storage, BigQuery, or Pub/Sub for long-term retention."
                    ),
                ))

        except ImportError:
            logger.warning("google-cloud-logging not installed; skipping Cloud Logging checks")
        except Exception as exc:
            logger.warning("GCP Cloud Logging sink check failed: %s", exc)
        return findings

    # ── Configuration review (orchestrates all checks) ────────────────────────

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        creds = self._credentials()
        project_id = self.credentials["project_id"]
        sc_client = securitycenter_v1.SecurityCenterClient(credentials=creds)
        org_id = self.credentials.get("org_id", "")
        findings = []

        # Security Command Center (opportunistic — requires org-level access)
        try:
            parent = f"organizations/{org_id}/sources/-" if org_id else f"projects/{project_id}/sources/-"
            request = securitycenter_v1.ListFindingsRequest(
                parent=parent,
                filter='state="ACTIVE"',
            )
            for result in sc_client.list_findings(request=request):
                f = result.finding
                sev = SEVERITY_MAP.get(str(f.severity.name), FindingSeverity.MEDIUM)
                findings.append(ConnectorFinding(
                    title=f.category,
                    description=f.description if hasattr(f, "description") else "",
                    severity=sev,
                    resource_id=f.resource_name,
                    resource_type=f.resource_name.split("/")[4] if "/" in f.resource_name else "",
                    framework="gcp_cis_benchmark",
                ))
        except Exception:
            pass

        # Direct rule library checks
        findings += self._check_gcs_buckets()
        findings += self._check_compute_firewall_rules()
        findings += self._check_iam_service_accounts()
        findings += self._check_cloud_logging()

        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        # GCP uses Container Analysis API for CVE findings
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
