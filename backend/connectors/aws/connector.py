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

    async def get_resources(self) -> List[Dict[str, Any]]:  # noqa: C901
        session = self._session()
        region = self.config.get("region", "ap-southeast-1")
        resources = []

        def _tag_name(tags, fallback=""):
            return next((t["Value"] for t in (tags or []) if t["Key"] == "Name"), fallback)

        # ── S3 Buckets ────────────────────────────────────────────────────────
        try:
            s3 = session.client("s3")
            for b in s3.list_buckets().get("Buckets", []):
                name = b["Name"]
                cfg: Dict[str, Any] = {}
                try:
                    cfg["versioning"] = s3.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
                except Exception:
                    pass
                try:
                    cfg["encryption"] = bool(s3.get_bucket_encryption(Bucket=name).get("ServerSideEncryptionConfiguration"))
                except Exception:
                    cfg["encryption"] = False
                try:
                    pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                    cfg["public_access_blocked"] = all([pab.get("BlockPublicAcls"), pab.get("BlockPublicPolicy"),
                                                        pab.get("IgnorePublicAcls"), pab.get("RestrictPublicBuckets")])
                except Exception:
                    pass
                try:
                    cfg["logging"] = bool(s3.get_bucket_logging(Bucket=name).get("LoggingEnabled"))
                except Exception:
                    pass
                resources.append({"id": f"arn:aws:s3:::{name}", "name": name, "type": "AWS::S3::Bucket", "location": "", "config": cfg})
        except Exception as exc:
            logger.debug("S3 failed: %s", exc)

        # ── EC2 Instances ─────────────────────────────────────────────────────
        try:
            ec2 = session.client("ec2")
            for page in ec2.get_paginator("describe_instances").paginate():
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        iid = inst.get("InstanceId", "")
                        resources.append({
                            "id": iid, "name": _tag_name(inst.get("Tags"), iid),
                            "type": "AWS::EC2::Instance",
                            "location": inst.get("Placement", {}).get("AvailabilityZone", region),
                            "config": {
                                "state": inst.get("State", {}).get("Name"),
                                "instance_type": inst.get("InstanceType"),
                                "public_ip": inst.get("PublicIpAddress"),
                                "private_ip": inst.get("PrivateIpAddress"),
                                "iam_profile": bool(inst.get("IamInstanceProfile")),
                                "ebs_optimized": inst.get("EbsOptimized"),
                                "monitoring": inst.get("Monitoring", {}).get("State"),
                                "platform": inst.get("Platform", "linux"),
                            },
                        })
        except Exception as exc:
            logger.debug("EC2 failed: %s", exc)

        # ── VPCs ──────────────────────────────────────────────────────────────
        try:
            ec2 = session.client("ec2")
            for page in ec2.get_paginator("describe_vpcs").paginate():
                for vpc in page.get("Vpcs", []):
                    vid = vpc.get("VpcId", "")
                    resources.append({
                        "id": vid, "name": _tag_name(vpc.get("Tags"), vid),
                        "type": "AWS::EC2::VPC", "location": region,
                        "config": {
                            "cidr": vpc.get("CidrBlock"),
                            "is_default": vpc.get("IsDefault"),
                            "state": vpc.get("State"),
                            "tenancy": vpc.get("InstanceTenancy"),
                        },
                    })
        except Exception as exc:
            logger.debug("VPC failed: %s", exc)

        # ── Security Groups ───────────────────────────────────────────────────
        try:
            ec2 = session.client("ec2")
            for page in ec2.get_paginator("describe_security_groups").paginate():
                for sg in page.get("SecurityGroups", []):
                    any_open = any(
                        any(r.get("CidrIp") == "0.0.0.0/0" or r.get("CidrIpv6") == "::/0"
                            for r in perm.get("IpRanges", []) + [{"CidrIpv6": x.get("CidrIpv6")} for x in perm.get("Ipv6Ranges", [])])
                        for perm in sg.get("IpPermissions", [])
                    )
                    resources.append({
                        "id": sg.get("GroupId", ""), "name": sg.get("GroupName", ""),
                        "type": "AWS::EC2::SecurityGroup", "location": region,
                        "config": {"vpc_id": sg.get("VpcId"), "has_open_inbound": any_open,
                                   "inbound_rule_count": len(sg.get("IpPermissions", []))},
                    })
        except Exception as exc:
            logger.debug("SecurityGroups failed: %s", exc)

        # ── Elastic Load Balancers (ALB/NLB) ──────────────────────────────────
        try:
            elbv2 = session.client("elbv2")
            for page in elbv2.get_paginator("describe_load_balancers").paginate():
                for lb in page.get("LoadBalancers", []):
                    resources.append({
                        "id": lb.get("LoadBalancerArn", ""), "name": lb.get("LoadBalancerName", ""),
                        "type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "location": region,
                        "config": {
                            "type": lb.get("Type"),
                            "scheme": lb.get("Scheme"),
                            "state": lb.get("State", {}).get("Code"),
                            "dns_name": lb.get("DNSName"),
                            "vpc_id": lb.get("VpcId"),
                        },
                    })
        except Exception as exc:
            logger.debug("ELBv2 failed: %s", exc)

        # ── RDS Instances ─────────────────────────────────────────────────────
        try:
            rds = session.client("rds")
            for page in rds.get_paginator("describe_db_instances").paginate():
                for db in page.get("DBInstances", []):
                    resources.append({
                        "id": db.get("DBInstanceArn", ""), "name": db.get("DBInstanceIdentifier", ""),
                        "type": "AWS::RDS::DBInstance", "location": db.get("AvailabilityZone", region),
                        "config": {
                            "engine": db.get("Engine"), "engine_version": db.get("EngineVersion"),
                            "instance_class": db.get("DBInstanceClass"),
                            "publicly_accessible": db.get("PubliclyAccessible"),
                            "storage_encrypted": db.get("StorageEncrypted"),
                            "multi_az": db.get("MultiAZ"),
                            "backup_retention_days": db.get("BackupRetentionPeriod"),
                            "deletion_protection": db.get("DeletionProtection"),
                        },
                    })
        except Exception as exc:
            logger.debug("RDS failed: %s", exc)

        # ── DynamoDB Tables ───────────────────────────────────────────────────
        try:
            ddb = session.client("dynamodb")
            for page in ddb.get_paginator("list_tables").paginate():
                for tname in page.get("TableNames", []):
                    try:
                        tbl = ddb.describe_table(TableName=tname).get("Table", {})
                        resources.append({
                            "id": tbl.get("TableArn", tname), "name": tname,
                            "type": "AWS::DynamoDB::Table", "location": region,
                            "config": {
                                "status": tbl.get("TableStatus"),
                                "item_count": tbl.get("ItemCount"),
                                "size_bytes": tbl.get("TableSizeBytes"),
                                "billing_mode": tbl.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"),
                                "point_in_time_recovery": tbl.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus"),
                            },
                        })
                    except Exception:
                        pass
        except Exception as exc:
            logger.debug("DynamoDB failed: %s", exc)

        # ── Lambda Functions ──────────────────────────────────────────────────
        try:
            lam = session.client("lambda")
            for page in lam.get_paginator("list_functions").paginate():
                for fn in page.get("Functions", []):
                    resources.append({
                        "id": fn.get("FunctionArn", ""), "name": fn.get("FunctionName", ""),
                        "type": "AWS::Lambda::Function", "location": region,
                        "config": {
                            "runtime": fn.get("Runtime"), "handler": fn.get("Handler"),
                            "memory_mb": fn.get("MemorySize"), "timeout_sec": fn.get("Timeout"),
                            "last_modified": fn.get("LastModified"),
                            "code_size_bytes": fn.get("CodeSize"),
                            "role": fn.get("Role"),
                            "package_type": fn.get("PackageType"),
                        },
                    })
        except Exception as exc:
            logger.debug("Lambda failed: %s", exc)

        # ── EKS Clusters ──────────────────────────────────────────────────────
        try:
            eks = session.client("eks")
            for name in eks.list_clusters().get("clusters", []):
                try:
                    cl = eks.describe_cluster(name=name).get("cluster", {})
                    resources.append({
                        "id": cl.get("arn", name), "name": name,
                        "type": "AWS::EKS::Cluster", "location": region,
                        "config": {
                            "status": cl.get("status"),
                            "k8s_version": cl.get("version"),
                            "endpoint_public": cl.get("resourcesVpcConfig", {}).get("endpointPublicAccess"),
                            "endpoint_private": cl.get("resourcesVpcConfig", {}).get("endpointPrivateAccess"),
                            "logging_enabled": bool(cl.get("logging", {}).get("clusterLogging")),
                            "secrets_encrypted": bool(cl.get("encryptionConfig")),
                        },
                    })
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("EKS failed: %s", exc)

        # ── ECS Clusters ──────────────────────────────────────────────────────
        try:
            ecs = session.client("ecs")
            arns = []
            for page in ecs.get_paginator("list_clusters").paginate():
                arns += page.get("clusterArns", [])
            if arns:
                for cl in ecs.describe_clusters(clusters=arns).get("clusters", []):
                    resources.append({
                        "id": cl.get("clusterArn", ""), "name": cl.get("clusterName", ""),
                        "type": "AWS::ECS::Cluster", "location": region,
                        "config": {
                            "status": cl.get("status"),
                            "running_tasks": cl.get("runningTasksCount"),
                            "pending_tasks": cl.get("pendingTasksCount"),
                            "active_services": cl.get("activeServicesCount"),
                        },
                    })
        except Exception as exc:
            logger.debug("ECS failed: %s", exc)

        # ── SQS Queues ────────────────────────────────────────────────────────
        try:
            sqs = session.client("sqs")
            for page in sqs.get_paginator("list_queues").paginate():
                for url in page.get("QueueUrls", []):
                    name = url.split("/")[-1]
                    resources.append({
                        "id": url, "name": name,
                        "type": "AWS::SQS::Queue", "location": region,
                        "config": {"url": url, "is_fifo": name.endswith(".fifo")},
                    })
        except Exception as exc:
            logger.debug("SQS failed: %s", exc)

        # ── SNS Topics ────────────────────────────────────────────────────────
        try:
            sns = session.client("sns")
            for page in sns.get_paginator("list_topics").paginate():
                for t in page.get("Topics", []):
                    arn = t.get("TopicArn", "")
                    resources.append({
                        "id": arn, "name": arn.split(":")[-1],
                        "type": "AWS::SNS::Topic", "location": region,
                        "config": {"arn": arn},
                    })
        except Exception as exc:
            logger.debug("SNS failed: %s", exc)

        # ── API Gateway (REST APIs) ────────────────────────────────────────────
        try:
            apigw = session.client("apigateway")
            for page in apigw.get_paginator("get_rest_apis").paginate():
                for api in page.get("items", []):
                    resources.append({
                        "id": api.get("id", ""), "name": api.get("name", ""),
                        "type": "AWS::ApiGateway::RestApi", "location": region,
                        "config": {
                            "description": api.get("description"),
                            "endpoint_type": api.get("endpointConfiguration", {}).get("types", [None])[0],
                            "created_date": str(api.get("createdDate", "")),
                        },
                    })
        except Exception as exc:
            logger.debug("APIGateway failed: %s", exc)

        # ── CloudFront Distributions ──────────────────────────────────────────
        try:
            cf = session.client("cloudfront")
            for page in cf.get_paginator("list_distributions").paginate():
                for dist in page.get("DistributionList", {}).get("Items", []):
                    resources.append({
                        "id": dist.get("ARN", ""), "name": dist.get("DomainName", ""),
                        "type": "AWS::CloudFront::Distribution", "location": "global",
                        "config": {
                            "status": dist.get("Status"),
                            "domain_name": dist.get("DomainName"),
                            "https_only": dist.get("ViewerCertificate", {}).get("MinimumProtocolVersion"),
                            "waf_enabled": bool(dist.get("WebACLId")),
                            "price_class": dist.get("PriceClass"),
                        },
                    })
        except Exception as exc:
            logger.debug("CloudFront failed: %s", exc)

        # ── Route53 Hosted Zones ──────────────────────────────────────────────
        try:
            r53 = session.client("route53")
            for page in r53.get_paginator("list_hosted_zones").paginate():
                for zone in page.get("HostedZones", []):
                    resources.append({
                        "id": zone.get("Id", ""), "name": zone.get("Name", "").rstrip("."),
                        "type": "AWS::Route53::HostedZone", "location": "global",
                        "config": {
                            "record_count": zone.get("ResourceRecordSetCount"),
                            "private": zone.get("Config", {}).get("PrivateZone"),
                        },
                    })
        except Exception as exc:
            logger.debug("Route53 failed: %s", exc)

        # ── ElastiCache Clusters ──────────────────────────────────────────────
        try:
            ec_client = session.client("elasticache")
            for page in ec_client.get_paginator("describe_cache_clusters").paginate():
                for cl in page.get("CacheClusters", []):
                    resources.append({
                        "id": cl.get("ARN", cl.get("CacheClusterId", "")), "name": cl.get("CacheClusterId", ""),
                        "type": "AWS::ElastiCache::CacheCluster", "location": cl.get("PreferredAvailabilityZone", region),
                        "config": {
                            "engine": cl.get("Engine"), "engine_version": cl.get("EngineVersion"),
                            "status": cl.get("CacheClusterStatus"),
                            "node_type": cl.get("CacheNodeType"),
                            "num_nodes": cl.get("NumCacheNodes"),
                            "at_rest_encrypted": cl.get("AtRestEncryptionEnabled"),
                            "transit_encrypted": cl.get("TransitEncryptionEnabled"),
                        },
                    })
        except Exception as exc:
            logger.debug("ElastiCache failed: %s", exc)

        # ── Kinesis Streams ───────────────────────────────────────────────────
        try:
            kin = session.client("kinesis")
            for page in kin.get_paginator("list_streams").paginate():
                for sname in page.get("StreamNames", []):
                    try:
                        s = kin.describe_stream_summary(StreamName=sname).get("StreamDescriptionSummary", {})
                        resources.append({
                            "id": s.get("StreamARN", sname), "name": sname,
                            "type": "AWS::Kinesis::Stream", "location": region,
                            "config": {
                                "status": s.get("StreamStatus"),
                                "shard_count": s.get("OpenShardCount"),
                                "retention_hours": s.get("RetentionPeriodHours"),
                                "encryption_type": s.get("EncryptionType"),
                            },
                        })
                    except Exception:
                        pass
        except Exception as exc:
            logger.debug("Kinesis failed: %s", exc)

        # ── Secrets Manager ───────────────────────────────────────────────────
        try:
            sm = session.client("secretsmanager")
            for page in sm.get_paginator("list_secrets").paginate():
                for sec in page.get("SecretList", []):
                    resources.append({
                        "id": sec.get("ARN", ""), "name": sec.get("Name", ""),
                        "type": "AWS::SecretsManager::Secret", "location": region,
                        "config": {
                            "rotation_enabled": sec.get("RotationEnabled"),
                            "last_rotated": str(sec.get("LastRotatedDate", "")),
                            "last_accessed": str(sec.get("LastAccessedDate", "")),
                        },
                    })
        except Exception as exc:
            logger.debug("SecretsManager failed: %s", exc)

        # ── KMS Keys ──────────────────────────────────────────────────────────
        try:
            kms = session.client("kms")
            for page in kms.get_paginator("list_keys").paginate():
                for k in page.get("Keys", []):
                    try:
                        meta = kms.describe_key(KeyId=k["KeyId"]).get("KeyMetadata", {})
                        if meta.get("KeyState") != "Enabled":
                            continue
                        resources.append({
                            "id": meta.get("Arn", k["KeyId"]), "name": meta.get("Description") or k["KeyId"],
                            "type": "AWS::KMS::Key", "location": region,
                            "config": {
                                "key_usage": meta.get("KeyUsage"),
                                "key_spec": meta.get("KeySpec"),
                                "origin": meta.get("Origin"),
                                "rotation_enabled": meta.get("KeyRotationStatus"),
                                "key_manager": meta.get("KeyManager"),
                            },
                        })
                    except Exception:
                        pass
        except Exception as exc:
            logger.debug("KMS failed: %s", exc)

        # ── ECR Repositories ──────────────────────────────────────────────────
        try:
            ecr = session.client("ecr")
            for page in ecr.get_paginator("describe_repositories").paginate():
                for repo in page.get("repositories", []):
                    resources.append({
                        "id": repo.get("repositoryArn", ""), "name": repo.get("repositoryName", ""),
                        "type": "AWS::ECR::Repository", "location": region,
                        "config": {
                            "uri": repo.get("repositoryUri"),
                            "image_tag_mutability": repo.get("imageTagMutability"),
                            "scan_on_push": repo.get("imageScanningConfiguration", {}).get("scanOnPush"),
                            "encryption_type": repo.get("encryptionConfiguration", {}).get("encryptionType"),
                        },
                    })
        except Exception as exc:
            logger.debug("ECR failed: %s", exc)

        # ── Redshift Clusters ─────────────────────────────────────────────────
        try:
            rs = session.client("redshift")
            for page in rs.get_paginator("describe_clusters").paginate():
                for cl in page.get("Clusters", []):
                    resources.append({
                        "id": cl.get("ClusterNamespaceArn", cl.get("ClusterIdentifier", "")),
                        "name": cl.get("ClusterIdentifier", ""),
                        "type": "AWS::Redshift::Cluster", "location": cl.get("AvailabilityZone", region),
                        "config": {
                            "status": cl.get("ClusterStatus"),
                            "node_type": cl.get("NodeType"),
                            "number_of_nodes": cl.get("NumberOfNodes"),
                            "publicly_accessible": cl.get("PubliclyAccessible"),
                            "encrypted": cl.get("Encrypted"),
                            "db_name": cl.get("DBName"),
                        },
                    })
        except Exception as exc:
            logger.debug("Redshift failed: %s", exc)

        # ── OpenSearch / Elasticsearch Domains ────────────────────────────────
        try:
            oss = session.client("opensearch")
            for domain_info in oss.list_domain_names().get("DomainNames", []):
                try:
                    d = oss.describe_domain(DomainName=domain_info["DomainName"]).get("DomainStatus", {})
                    resources.append({
                        "id": d.get("ARN", ""), "name": d.get("DomainName", ""),
                        "type": "AWS::OpenSearchService::Domain", "location": region,
                        "config": {
                            "engine_version": d.get("EngineVersion"),
                            "processing": d.get("Processing"),
                            "endpoint": d.get("Endpoint"),
                            "encryption_at_rest": d.get("EncryptionAtRestOptions", {}).get("Enabled"),
                            "node_to_node_encryption": d.get("NodeToNodeEncryptionOptions", {}).get("Enabled"),
                            "enforce_https": d.get("DomainEndpointOptions", {}).get("EnforceHTTPS"),
                        },
                    })
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("OpenSearch failed: %s", exc)

        # ── CloudFormation Stacks ─────────────────────────────────────────────
        try:
            cfn = session.client("cloudformation")
            for page in cfn.get_paginator("describe_stacks").paginate():
                for stack in page.get("Stacks", []):
                    if stack.get("StackStatus") in ("DELETE_COMPLETE",):
                        continue
                    resources.append({
                        "id": stack.get("StackId", ""), "name": stack.get("StackName", ""),
                        "type": "AWS::CloudFormation::Stack", "location": region,
                        "config": {
                            "status": stack.get("StackStatus"),
                            "drift_status": stack.get("DriftInformation", {}).get("StackDriftStatus"),
                            "termination_protection": stack.get("EnableTerminationProtection"),
                            "resource_count": len(stack.get("Outputs", [])),
                        },
                    })
        except Exception as exc:
            logger.debug("CloudFormation failed: %s", exc)

        # ── Step Functions State Machines ─────────────────────────────────────
        try:
            sfn = session.client("stepfunctions")
            for page in sfn.get_paginator("list_state_machines").paginate():
                for sm in page.get("stateMachines", []):
                    resources.append({
                        "id": sm.get("stateMachineArn", ""), "name": sm.get("name", ""),
                        "type": "AWS::StepFunctions::StateMachine", "location": region,
                        "config": {
                            "type": sm.get("type"),
                            "creation_date": str(sm.get("creationDate", "")),
                        },
                    })
        except Exception as exc:
            logger.debug("StepFunctions failed: %s", exc)

        # ── EventBridge Rules ─────────────────────────────────────────────────
        try:
            eb = session.client("events")
            for page in eb.get_paginator("list_rules").paginate():
                for rule in page.get("Rules", []):
                    resources.append({
                        "id": rule.get("Arn", ""), "name": rule.get("Name", ""),
                        "type": "AWS::Events::Rule", "location": region,
                        "config": {
                            "state": rule.get("State"),
                            "schedule": rule.get("ScheduleExpression"),
                            "event_pattern": bool(rule.get("EventPattern")),
                        },
                    })
        except Exception as exc:
            logger.debug("EventBridge failed: %s", exc)

        # ── Cognito User Pools ────────────────────────────────────────────────
        try:
            cog = session.client("cognito-idp")
            for page in cog.get_paginator("list_user_pools").paginate(MaxResults=60):
                for pool in page.get("UserPools", []):
                    resources.append({
                        "id": pool.get("Id", ""), "name": pool.get("Name", ""),
                        "type": "AWS::Cognito::UserPool", "location": region,
                        "config": {
                            "status": pool.get("Status"),
                            "last_modified": str(pool.get("LastModifiedDate", "")),
                            "creation_date": str(pool.get("CreationDate", "")),
                        },
                    })
        except Exception as exc:
            logger.debug("Cognito failed: %s", exc)

        # ── IAM Users ─────────────────────────────────────────────────────────
        try:
            iam = session.client("iam")
            for page in iam.get_paginator("list_users").paginate():
                for u in page.get("Users", []):
                    resources.append({
                        "id": u.get("Arn", ""), "name": u.get("UserName", ""),
                        "type": "AWS::IAM::User", "location": "global",
                        "config": {
                            "path": u.get("Path"),
                            "password_last_used": str(u.get("PasswordLastUsed", "")),
                            "has_mfa": None,
                        },
                    })
        except Exception as exc:
            logger.debug("IAM Users failed: %s", exc)

        # ── IAM Roles ─────────────────────────────────────────────────────────
        try:
            iam = session.client("iam")
            for page in iam.get_paginator("list_roles").paginate():
                for role in page.get("Roles", []):
                    if role.get("Path", "").startswith("/aws-service-role/"):
                        continue
                    resources.append({
                        "id": role.get("Arn", ""), "name": role.get("RoleName", ""),
                        "type": "AWS::IAM::Role", "location": "global",
                        "config": {
                            "path": role.get("Path"),
                            "description": role.get("Description", ""),
                            "max_session_duration": role.get("MaxSessionDuration"),
                        },
                    })
        except Exception as exc:
            logger.debug("IAM Roles failed: %s", exc)

        # ── Glue Jobs ─────────────────────────────────────────────────────────
        try:
            glue = session.client("glue")
            for page in glue.get_paginator("get_jobs").paginate():
                for job in page.get("Jobs", []):
                    resources.append({
                        "id": f"arn:aws:glue:{region}::job/{job.get('Name', '')}",
                        "name": job.get("Name", ""),
                        "type": "AWS::Glue::Job", "location": region,
                        "config": {
                            "role": job.get("Role"),
                            "worker_type": job.get("WorkerType"),
                            "glue_version": job.get("GlueVersion"),
                            "max_retries": job.get("MaxRetries"),
                        },
                    })
        except Exception as exc:
            logger.debug("Glue failed: %s", exc)

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
