"""
NexGenCyberAI - AWS Connector
Uses boto3 with IAM Role assumption or static access keys.
Pulls AWS Security Hub findings, Config rules, Inspector2, GuardDuty.
"""
import logging
from typing import Any, Dict, List
import boto3
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
    "INFORMATIONAL": FindingSeverity.INFO,
}

# Port → (service name, severity)
RISKY_PORTS_AWS: Dict[int, tuple] = {
    22:    ("SSH",           FindingSeverity.HIGH),
    3389:  ("RDP",           FindingSeverity.CRITICAL),
    3306:  ("MySQL",         FindingSeverity.HIGH),
    5432:  ("PostgreSQL",    FindingSeverity.HIGH),
    1433:  ("MSSQL",         FindingSeverity.HIGH),
    6379:  ("Redis",         FindingSeverity.HIGH),
    27017: ("MongoDB",       FindingSeverity.HIGH),
    9200:  ("Elasticsearch", FindingSeverity.HIGH),
    23:    ("Telnet",        FindingSeverity.CRITICAL),
}


class AWSConnector(BaseConnector):

    def _session(self):
        if self.credentials.get("role_arn"):
            sts = boto3.client(
                "sts",
                aws_access_key_id=self.credentials.get("access_key_id"),
                aws_secret_access_key=self.credentials.get("secret_access_key"),
                region_name=self.config.get("region", "us-east-1"),
            )
            assumed = sts.assume_role(
                RoleArn=self.credentials["role_arn"],
                RoleSessionName="NexGenCyberAI",
            )
            creds = assumed["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.config.get("region", "us-east-1"),
            )
        return boto3.Session(
            aws_access_key_id=self.credentials.get("access_key_id"),
            aws_secret_access_key=self.credentials.get("secret_access_key"),
            region_name=self.config.get("region", "us-east-1"),
        )

    async def test_connection(self) -> ConnectorTestResult:
        try:
            session = self._session()
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            return ConnectorTestResult(
                success=True,
                message=f"Connected as {identity['Arn']}",
                details={"account": identity["Account"], "arn": identity["Arn"]},
            )
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    async def get_resources(self) -> List[Dict[str, Any]]:
        session = self._session()
        resources = []
        # EC2 instances
        ec2 = session.client("ec2")
        resp = ec2.describe_instances()
        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                resources.append({
                    "id": inst["InstanceId"],
                    "name": next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"]),
                    "type": "ec2_instance",
                    "state": inst["State"]["Name"],
                    "region": self.config.get("region", "us-east-1"),
                })
        # S3 buckets
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            resources.append({"id": b["Name"], "name": b["Name"], "type": "s3_bucket"})
        return resources

    # ── S3 Buckets ────────────────────────────────────────────────────────────

    def _check_s3_buckets(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            session = self._session()
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket["Name"]
                # Per-bucket checks wrapped individually — buckets may be in different regions
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                            findings.append(ConnectorFinding(
                                title=f"S3 bucket '{name}' is publicly accessible via ACL",
                                description=(
                                    f"The bucket ACL grants access to the AllUsers group "
                                    f"(http://acs.amazonaws.com/groups/global/AllUsers). "
                                    f"Any unauthenticated internet user can read or write objects."
                                ),
                                severity=FindingSeverity.CRITICAL,
                                resource_id=f"arn:aws:s3:::{name}",
                                resource_type="AWS::S3::Bucket",
                                control_id="NIST AC-3",
                                framework="nist",
                                remediation="Remove the AllUsers grant from the bucket ACL and enable S3 Block Public Access.",
                            ))
                except Exception as exc:
                    logger.warning("S3 ACL check failed for bucket '%s': %s", name, exc)

                try:
                    enc_resp = s3.get_bucket_encryption(Bucket=name)
                    if not enc_resp.get("ServerSideEncryptionConfiguration"):
                        findings.append(ConnectorFinding(
                            title=f"S3 bucket '{name}' has no default server-side encryption",
                            description=(
                                f"No default server-side encryption rule is configured for bucket '{name}'. "
                                f"Objects stored without explicit encryption keys are written in plaintext."
                            ),
                            severity=FindingSeverity.HIGH,
                            resource_id=f"arn:aws:s3:::{name}",
                            resource_type="AWS::S3::Bucket",
                            control_id="NIST SC-28",
                            framework="nist",
                            remediation="Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                        ))
                except s3.exceptions.ClientError as exc:
                    error_code = exc.response.get("Error", {}).get("Code", "")
                    if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                        findings.append(ConnectorFinding(
                            title=f"S3 bucket '{name}' has no default server-side encryption",
                            description=(
                                f"No default server-side encryption rule is configured for bucket '{name}'. "
                                f"Objects stored without explicit encryption keys are written in plaintext."
                            ),
                            severity=FindingSeverity.HIGH,
                            resource_id=f"arn:aws:s3:::{name}",
                            resource_type="AWS::S3::Bucket",
                            control_id="NIST SC-28",
                            framework="nist",
                            remediation="Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                        ))
                    else:
                        logger.warning("S3 encryption check failed for bucket '%s': %s", name, exc)
                except Exception as exc:
                    logger.warning("S3 encryption check failed for bucket '%s': %s", name, exc)

                try:
                    ver_resp = s3.get_bucket_versioning(Bucket=name)
                    if ver_resp.get("Status") != "Enabled":
                        findings.append(ConnectorFinding(
                            title=f"S3 bucket '{name}' has versioning disabled",
                            description=(
                                f"Versioning is not enabled on bucket '{name}'. "
                                f"Accidental deletions or overwrites cannot be recovered."
                            ),
                            severity=FindingSeverity.LOW,
                            resource_id=f"arn:aws:s3:::{name}",
                            resource_type="AWS::S3::Bucket",
                            control_id="NIST SC-28",
                            framework="nist",
                            remediation="Enable S3 versioning on the bucket to protect against accidental data loss.",
                        ))
                except Exception as exc:
                    logger.warning("S3 versioning check failed for bucket '%s': %s", name, exc)

                try:
                    log_resp = s3.get_bucket_logging(Bucket=name)
                    if not log_resp.get("LoggingEnabled"):
                        findings.append(ConnectorFinding(
                            title=f"S3 bucket '{name}' has access logging disabled",
                            description=(
                                f"Server access logging is not enabled for bucket '{name}'. "
                                f"Without access logs, unauthorized or anomalous access cannot be detected or investigated."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            resource_id=f"arn:aws:s3:::{name}",
                            resource_type="AWS::S3::Bucket",
                            control_id="NIST AU-2",
                            framework="nist",
                            remediation="Enable S3 server access logging and direct logs to a dedicated audit bucket.",
                        ))
                except Exception as exc:
                    logger.warning("S3 logging check failed for bucket '%s': %s", name, exc)

        except ImportError:
            logger.warning("boto3 not installed; skipping S3 bucket checks")
        except Exception as exc:
            logger.warning("S3 bucket scan failed: %s", exc)
        return findings

    # ── IAM Policies ──────────────────────────────────────────────────────────

    def _check_iam_policies(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            session = self._session()
            iam = session.client("iam")

            # Check IAM users for overly permissive directly attached policies
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    try:
                        # Managed policies attached directly to user
                        attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                        for policy in attached:
                            policy_name = policy["PolicyName"]
                            if "AdministratorAccess" in policy_name or "FullAccess" in policy_name:
                                findings.append(ConnectorFinding(
                                    title=f"IAM user '{username}' has overly permissive policy '{policy_name}' attached directly",
                                    description=(
                                        f"The policy '{policy_name}' is attached directly to IAM user '{username}'. "
                                        f"Direct user policy attachment bypasses group-based access management "
                                        f"and violates least-privilege principles."
                                    ),
                                    severity=FindingSeverity.HIGH,
                                    resource_id=user.get("Arn", username),
                                    resource_type="AWS::IAM::User",
                                    control_id="NIST AC-6",
                                    framework="nist",
                                    remediation=(
                                        f"Remove the '{policy_name}' policy from user '{username}'. "
                                        f"Use IAM groups with scoped permissions instead."
                                    ),
                                ))
                    except Exception as exc:
                        logger.warning("IAM attached policy check failed for user '%s': %s", username, exc)

                    try:
                        # Inline policies on user
                        inline = iam.list_user_policies(UserName=username).get("PolicyNames", [])
                        for policy_name in inline:
                            if "AdministratorAccess" in policy_name or "FullAccess" in policy_name:
                                findings.append(ConnectorFinding(
                                    title=f"IAM user '{username}' has overly permissive policy '{policy_name}' attached directly",
                                    description=(
                                        f"The inline policy '{policy_name}' is attached directly to IAM user '{username}'. "
                                        f"Direct user policy attachment violates least-privilege principles."
                                    ),
                                    severity=FindingSeverity.HIGH,
                                    resource_id=user.get("Arn", username),
                                    resource_type="AWS::IAM::User",
                                    control_id="NIST AC-6",
                                    framework="nist",
                                    remediation=(
                                        f"Remove the inline policy '{policy_name}' from user '{username}'. "
                                        f"Use IAM groups with scoped permissions instead."
                                    ),
                                ))
                    except Exception as exc:
                        logger.warning("IAM inline policy check failed for user '%s': %s", username, exc)

            # Check IAM roles for wildcard trust policies
            role_paginator = iam.get_paginator("list_roles")
            for page in role_paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    trust_doc = role.get("AssumeRolePolicyDocument", {})
                    for statement in trust_doc.get("Statement", []):
                        principal = statement.get("Principal", {})
                        effect = statement.get("Effect", "")
                        # Principal: "*" means any AWS principal can assume the role
                        if effect == "Allow" and (
                            principal == "*"
                            or (isinstance(principal, dict) and principal.get("AWS") == "*")
                        ):
                            findings.append(ConnectorFinding(
                                title=f"IAM role '{role_name}' can be assumed by any AWS principal",
                                description=(
                                    f"The trust policy of IAM role '{role_name}' allows any AWS principal "
                                    f"(Principal: '*') to assume the role. This is a critical misconfiguration "
                                    f"that may grant attackers unrestricted access to the role's permissions."
                                ),
                                severity=FindingSeverity.CRITICAL,
                                resource_id=role.get("Arn", role_name),
                                resource_type="AWS::IAM::Role",
                                control_id="NIST AC-2",
                                framework="nist",
                                remediation=(
                                    f"Update the trust policy of role '{role_name}' to restrict the Principal "
                                    f"to specific AWS accounts, services, or IAM principals."
                                ),
                            ))

        except ImportError:
            logger.warning("boto3 not installed; skipping IAM policy checks")
        except Exception as exc:
            logger.warning("IAM policy scan failed: %s", exc)
        return findings

    # ── Security Groups ───────────────────────────────────────────────────────

    def _check_security_groups(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            session = self._session()
            ec2 = session.client("ec2")
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg.get("GroupId", "")
                    sg_name = sg.get("GroupName", sg_id)
                    for rule in sg.get("IpPermissions", []):
                        from_port = rule.get("FromPort", -1)
                        to_port = rule.get("ToPort", -1)
                        ip_protocol = rule.get("IpProtocol", "")

                        # Collect open CIDR sources
                        open_sources = []
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                open_sources.append("0.0.0.0/0")
                        for ipv6_range in rule.get("Ipv6Ranges", []):
                            if ipv6_range.get("CidrIpv6") == "::/0":
                                open_sources.append("::/0")

                        if not open_sources:
                            continue

                        # All traffic rule (protocol -1 or port -1 to -1)
                        if ip_protocol == "-1" or (from_port == -1 and to_port == -1):
                            findings.append(ConnectorFinding(
                                title=f"Security group '{sg_name}' allows all inbound traffic from internet",
                                description=(
                                    f"Security group '{sg_name}' ({sg_id}) has a rule that allows all inbound "
                                    f"traffic from {', '.join(open_sources)}. This exposes all ports and protocols "
                                    f"to the public internet."
                                ),
                                severity=FindingSeverity.CRITICAL,
                                resource_id=sg_id,
                                resource_type="AWS::EC2::SecurityGroup",
                                control_id="NIST SC-7",
                                framework="nist",
                                remediation=(
                                    f"Remove the catch-all inbound rule from security group '{sg_name}'. "
                                    f"Define explicit rules for only the ports and sources required."
                                ),
                            ))
                            continue

                        # Check specific risky ports
                        for port, (svc, sev) in RISKY_PORTS_AWS.items():
                            port_in_rule = False
                            if from_port == -1 and to_port == -1:
                                port_in_rule = True
                            elif from_port is not None and to_port is not None:
                                try:
                                    port_in_rule = int(from_port) <= port <= int(to_port)
                                except (ValueError, TypeError):
                                    pass
                            if port_in_rule:
                                findings.append(ConnectorFinding(
                                    title=f"Security group '{sg_name}' allows inbound {svc} (port {port}) from internet",
                                    description=(
                                        f"Security group '{sg_name}' ({sg_id}) permits inbound {svc} traffic "
                                        f"on port {port} from {', '.join(open_sources)}. "
                                        f"This exposes the service to brute-force and exploitation from the internet."
                                    ),
                                    severity=sev,
                                    resource_id=sg_id,
                                    resource_type="AWS::EC2::SecurityGroup",
                                    control_id="NIST SC-7",
                                    framework="nist",
                                    remediation=(
                                        f"Restrict the inbound rule for port {port} in security group '{sg_name}' "
                                        f"to known IP ranges. Use a bastion host or VPN for administrative access."
                                    ),
                                ))

        except ImportError:
            logger.warning("boto3 not installed; skipping security group checks")
        except Exception as exc:
            logger.warning("Security group scan failed: %s", exc)
        return findings

    # ── CloudTrail ────────────────────────────────────────────────────────────

    def _check_cloudtrail(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            session = self._session()
            ct = session.client("cloudtrail")
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

            if not trails:
                findings.append(ConnectorFinding(
                    title="AWS CloudTrail is not configured in this region",
                    description=(
                        "No CloudTrail trails are configured in this region. "
                        "Without CloudTrail, API calls and management events are not logged, "
                        "making it impossible to detect or investigate unauthorized activity."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_id=f"aws:cloudtrail:{self.config.get('region', 'us-east-1')}",
                    resource_type="AWS::CloudTrail::Trail",
                    control_id="NIST AU-2",
                    framework="nist",
                    remediation="Create a CloudTrail trail covering all regions and deliver logs to an S3 bucket.",
                ))
                return findings

            for trail in trails:
                trail_name = trail.get("Name", "")
                trail_arn = trail.get("TrailARN", trail_name)

                try:
                    status = ct.get_trail_status(Name=trail_arn)
                    if not status.get("IsLogging", False):
                        findings.append(ConnectorFinding(
                            title=f"CloudTrail trail '{trail_name}' is not actively logging",
                            description=(
                                f"CloudTrail trail '{trail_name}' exists but logging is currently stopped. "
                                f"API calls and management events are not being recorded."
                            ),
                            severity=FindingSeverity.HIGH,
                            resource_id=trail_arn,
                            resource_type="AWS::CloudTrail::Trail",
                            control_id="NIST AU-2",
                            framework="nist",
                            remediation=f"Start logging on CloudTrail trail '{trail_name}' immediately.",
                        ))
                except Exception as exc:
                    logger.warning("CloudTrail status check failed for trail '%s': %s", trail_name, exc)

                if not trail.get("LogFileValidationEnabled", False):
                    findings.append(ConnectorFinding(
                        title=f"CloudTrail trail '{trail_name}' has log file validation disabled",
                        description=(
                            f"Log file validation is not enabled for trail '{trail_name}'. "
                            f"Without validation, log files could be tampered with and the tampering would go undetected."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        resource_id=trail_arn,
                        resource_type="AWS::CloudTrail::Trail",
                        control_id="NIST AU-2",
                        framework="nist",
                        remediation=f"Enable log file validation on CloudTrail trail '{trail_name}'.",
                    ))

        except ImportError:
            logger.warning("boto3 not installed; skipping CloudTrail checks")
        except Exception as exc:
            logger.warning("CloudTrail scan failed: %s", exc)
        return findings

    # ── RDS Instances ─────────────────────────────────────────────────────────

    def _check_rds_instances(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            session = self._session()
            rds = session.client("rds")
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    db_id = db.get("DBInstanceIdentifier", "")
                    db_arn = db.get("DBInstanceArn", db_id)
                    db_class = db.get("DBInstanceClass", "")

                    if db.get("PubliclyAccessible", False):
                        findings.append(ConnectorFinding(
                            title=f"RDS instance '{db_id}' is publicly accessible",
                            description=(
                                f"RDS instance '{db_id}' has PubliclyAccessible set to true. "
                                f"The database endpoint resolves to a public IP address and is reachable from the internet."
                            ),
                            severity=FindingSeverity.HIGH,
                            resource_id=db_arn,
                            resource_type="AWS::RDS::DBInstance",
                            control_id="NIST SC-7",
                            framework="nist",
                            remediation=(
                                f"Modify RDS instance '{db_id}' to disable public accessibility. "
                                f"Use a private subnet and VPC security groups to control access."
                            ),
                        ))

                    if not db.get("StorageEncrypted", True):
                        findings.append(ConnectorFinding(
                            title=f"RDS instance '{db_id}' has unencrypted storage",
                            description=(
                                f"RDS instance '{db_id}' does not have storage encryption enabled. "
                                f"Data at rest including database files, logs, and automated backups is stored in plaintext."
                            ),
                            severity=FindingSeverity.HIGH,
                            resource_id=db_arn,
                            resource_type="AWS::RDS::DBInstance",
                            control_id="NIST SC-28",
                            framework="nist",
                            remediation=(
                                f"Enable encryption for RDS instance '{db_id}'. "
                                f"Note: encryption can only be enabled at creation time — "
                                f"create an encrypted snapshot and restore to a new encrypted instance."
                            ),
                        ))

                    # Multi-AZ check — skip micro/small instances (cost-constrained)
                    if not db.get("MultiAZ", False):
                        is_small = any(size in db_class for size in ("micro", "small"))
                        if not is_small:
                            findings.append(ConnectorFinding(
                                title=f"RDS instance '{db_id}' is not configured for Multi-AZ (no HA)",
                                description=(
                                    f"RDS instance '{db_id}' ({db_class}) does not have Multi-AZ enabled. "
                                    f"A single-AZ instance has no automatic failover — an AZ outage causes downtime."
                                ),
                                severity=FindingSeverity.MEDIUM,
                                resource_id=db_arn,
                                resource_type="AWS::RDS::DBInstance",
                                control_id="NIST CP-10",
                                framework="nist",
                                remediation=f"Enable Multi-AZ for RDS instance '{db_id}' to ensure high availability.",
                            ))

                    if not db.get("AutoMinorVersionUpgrade", True):
                        findings.append(ConnectorFinding(
                            title=f"RDS instance '{db_id}' has auto minor version upgrade disabled",
                            description=(
                                f"RDS instance '{db_id}' will not automatically apply minor engine version upgrades. "
                                f"Minor upgrades frequently include security patches."
                            ),
                            severity=FindingSeverity.LOW,
                            resource_id=db_arn,
                            resource_type="AWS::RDS::DBInstance",
                            control_id="NIST SC-28",
                            framework="nist",
                            remediation=f"Enable AutoMinorVersionUpgrade on RDS instance '{db_id}'.",
                        ))

        except ImportError:
            logger.warning("boto3 not installed; skipping RDS instance checks")
        except Exception as exc:
            logger.warning("RDS instance scan failed: %s", exc)
        return findings

    # ── Configuration review (orchestrates all checks) ────────────────────────

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        session = self._session()
        findings = []
        # Security Hub (opportunistic — may not be enabled)
        try:
            hub = session.client("securityhub")
            paginator = hub.get_paginator("get_findings")
            for page in paginator.paginate(
                Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
                MaxResults=100,
            ):
                for f in page.get("Findings", []):
                    sev_label = f.get("Severity", {}).get("Label", "MEDIUM")
                    findings.append(ConnectorFinding(
                        title=f.get("Title", ""),
                        description=f.get("Description", ""),
                        severity=SEVERITY_MAP.get(sev_label, FindingSeverity.MEDIUM),
                        resource_id=f.get("Resources", [{}])[0].get("Id", "") if f.get("Resources") else "",
                        resource_type=f.get("Resources", [{}])[0].get("Type", "") if f.get("Resources") else "",
                        control_id=f.get("Compliance", {}).get("RelatedRequirements", [""])[0],
                        framework="aws_foundational_security",
                        remediation=f.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                    ))
        except Exception:
            pass

        # Direct rule library checks
        findings += self._check_s3_buckets()
        findings += self._check_iam_policies()
        findings += self._check_security_groups()
        findings += self._check_cloudtrail()
        findings += self._check_rds_instances()

        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        session = self._session()
        findings = []
        try:
            inspector = session.client("inspector2")
            paginator = inspector.get_paginator("list_findings")
            for page in paginator.paginate():
                for f in page.get("findings", []):
                    sev = f.get("severity", "MEDIUM")
                    vuln = f.get("packageVulnerabilityDetails", {})
                    findings.append(ConnectorFinding(
                        title=f.get("title", ""),
                        description=f.get("description", ""),
                        severity=SEVERITY_MAP.get(sev, FindingSeverity.MEDIUM),
                        resource_id=f.get("resources", [{}])[0].get("id", "") if f.get("resources") else "",
                        resource_type=f.get("resources", [{}])[0].get("type", "") if f.get("resources") else "",
                        cve_id=vuln.get("vulnerabilityId", ""),
                        cvss_score=float(vuln.get("cvss", [{}])[0].get("baseScore", 0)) if vuln.get("cvss") else 0.0,
                        framework="cve",
                    ))
        except Exception:
            pass
        return findings

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        session = self._session()
        results: Dict[str, Any] = {}
        try:
            hub = session.client("securityhub")
            standards = hub.get_enabled_standards().get("StandardsSubscriptions", [])
            for std in standards:
                if framework.lower() in std.get("StandardsArn", "").lower():
                    controls = hub.describe_standards_controls(
                        StandardsSubscriptionArn=std["StandardsSubscriptionArn"]
                    ).get("Controls", [])
                    for ctrl in controls:
                        results[ctrl["ControlId"]] = {
                            "status": ctrl.get("ControlStatus"),
                            "title": ctrl.get("Title"),
                        }
        except Exception:
            pass
        return results
