"""
NexGenCyberAI - AWS Connector
Uses boto3 with IAM Role assumption or static access keys.
Pulls AWS Security Hub findings, Config rules, Inspector2, GuardDuty.
"""
from typing import Any, Dict, List
import boto3
from ..base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

SEVERITY_MAP = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
    "INFORMATIONAL": FindingSeverity.INFO,
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

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        session = self._session()
        findings = []
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
