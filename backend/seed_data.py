"""
Seed sample data into NexGenCyberAI SQLite database.
Run once on the backend App Service to populate demo data.
Usage: python seed_data.py
"""
import sys
import os

# Determine DB path
DB_PATH = os.environ.get("DATABASE_URL", "sqlite:////home/nexgencyberai.db")
if DB_PATH.startswith("sqlite:///"):
    DB_PATH = DB_PATH[len("sqlite:///"):]
print(f"Using database: {DB_PATH}")

import sqlite3
from datetime import datetime, timedelta, timezone
import uuid
import json

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

def _uuid():
    return str(uuid.uuid4())

now = datetime.now(timezone.utc)
def dt(days_ago=0, hours_ago=0):
    return (now - timedelta(days=days_ago, hours=hours_ago)).isoformat()

# ── Check if already seeded ──────────────────────────────────────────────────
cur.execute("SELECT COUNT(*) FROM clients")
count = cur.fetchone()[0]
if count > 0:
    print(f"Database already has {count} clients — skipping seed.")
    conn.close()
    sys.exit(0)

print("Seeding sample data...")

# ── Clients ──────────────────────────────────────────────────────────────────
clients = [
    (_uuid(), "Acme Financial Services", "acme-financial", "Financial Services", "United Kingdom",
     "Sarah Mitchell", "s.mitchell@acmefinancial.co.uk"),
    (_uuid(), "TechCorp Global", "techcorp-global", "Technology", "United States",
     "James Hooper", "j.hooper@techcorpglobal.com"),
    (_uuid(), "MediCare NHS Trust", "medicare-nhs", "Healthcare", "United Kingdom",
     "Dr. Priya Sharma", "p.sharma@medicare-nhs.nhs.uk"),
    (_uuid(), "RetailOne Group", "retailone-group", "Retail", "Germany",
     "Klaus Weber", "k.weber@retailonegroup.de"),
]

for c in clients:
    cur.execute("""
        INSERT INTO clients (id, name, slug, industry, country, contact_name, contact_email,
                             is_active, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, '{}', ?)
    """, (*c, dt(days_ago=90)))

# ── Connectors ───────────────────────────────────────────────────────────────
c0, c1, c2, c3 = [c[0] for c in clients]

connectors = [
    (_uuid(), c0, "Acme Azure Production", "azure", "active", dt(days_ago=1)),
    (_uuid(), c0, "Acme Entra ID", "entraid", "active", dt(days_ago=2)),
    (_uuid(), c1, "TechCorp AWS East", "aws", "active", dt(days_ago=1)),
    (_uuid(), c1, "TechCorp GitHub", "github", "active", dt(days_ago=3)),
    (_uuid(), c2, "NHS Azure UK South", "azure", "active", dt(days_ago=1)),
    (_uuid(), c2, "NHS ServiceNow", "servicenow", "error", dt(days_ago=10)),
    (_uuid(), c3, "RetailOne GCP", "gcp", "active", dt(days_ago=2)),
    (_uuid(), c3, "RetailOne Containers", "containers", "pending", dt()),
]
connector_ids = [cn[0] for cn in connectors]

for cn in connectors:
    cur.execute("""
        INSERT INTO connectors (id, client_id, name, connector_type, status, last_synced_at, config, created_at)
        VALUES (?, ?, ?, ?, ?, ?, '{}', ?)
    """, (*cn, dt(days_ago=90)))

# ── Scans ────────────────────────────────────────────────────────────────────
scans = [
    (_uuid(), c0, connector_ids[0], "full", "completed", None, dt(days_ago=3), dt(days_ago=2),
     '{"total":142,"critical":8,"high":24,"medium":51,"low":59,"passed":89,"failed":53}'),
    (_uuid(), c0, connector_ids[0], "vulnerability", "completed", None, dt(days_ago=10), dt(days_ago=9),
     '{"total":67,"critical":3,"high":12,"medium":28,"low":24,"passed":44,"failed":23}'),
    (_uuid(), c0, connector_ids[0], "compliance", "completed", "nist_csf", dt(days_ago=5), dt(days_ago=5),
     '{"total":98,"critical":2,"high":10,"medium":30,"low":56,"passed":72,"failed":26}'),
    (_uuid(), c1, connector_ids[2], "full", "completed", None, dt(days_ago=2), dt(days_ago=1),
     '{"total":89,"critical":4,"high":18,"medium":33,"low":34,"passed":61,"failed":28}'),
    (_uuid(), c1, connector_ids[2], "compliance", "completed", "cis_v8", dt(days_ago=7), dt(days_ago=6),
     '{"total":113,"critical":1,"high":8,"medium":22,"low":82,"passed":95,"failed":18}'),
    (_uuid(), c2, connector_ids[4], "vulnerability", "completed", None, dt(days_ago=1), dt(hours_ago=18),
     '{"total":201,"critical":15,"high":42,"medium":68,"low":76,"passed":104,"failed":97}'),
    (_uuid(), c2, connector_ids[4], "compliance", "completed", "gdpr", dt(days_ago=4), dt(days_ago=3),
     '{"total":77,"critical":5,"high":21,"medium":28,"low":23,"passed":44,"failed":33}'),
    (_uuid(), c3, connector_ids[6], "configuration", "completed", None, dt(days_ago=5), dt(days_ago=4),
     '{"total":55,"critical":2,"high":9,"medium":19,"low":25,"passed":38,"failed":17}'),
    (_uuid(), c3, connector_ids[6], "compliance", "running", "pci_dss", dt(hours_ago=2), None,
     '{}'),
]
scan_ids = [s[0] for s in scans]

for s in scans:
    cur.execute("""
        INSERT INTO scans (id, client_id, connector_id, scan_type, status, framework,
                           started_at, completed_at, summary, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (*s, dt(days_ago=10)))

# ── Findings ─────────────────────────────────────────────────────────────────
findings_raw = [
    # Acme Financial - full scan
    (scan_ids[0], c0, "Unpatched Critical CVE in OpenSSL 3.0.x", "critical",
     "CVE-2023-0286", 9.8, "vm-acme-prod-001", "Virtual Machine",
     "Upgrade OpenSSL to 3.0.8 or later immediately."),
    (scan_ids[0], c0, "MFA Not Enforced for Admin Accounts", "critical",
     None, None, "Azure AD", "Identity",
     "Enable Conditional Access policy requiring MFA for all admin roles."),
    (scan_ids[0], c0, "Storage Account Allows Public Blob Access", "high",
     None, None, "acmefinprod-storage", "Storage Account",
     "Set 'allowBlobPublicAccess' to false on all storage accounts."),
    (scan_ids[0], c0, "Azure Key Vault Soft Delete Disabled", "high",
     None, None, "acme-kv-prod", "Key Vault",
     "Enable soft delete and purge protection on the Key Vault."),
    (scan_ids[0], c0, "Outdated TLS 1.0/1.1 Protocols Enabled", "medium",
     None, None, "acme-appsvc-prod", "App Service",
     "Disable TLS 1.0 and 1.1; enforce TLS 1.2 minimum."),
    (scan_ids[0], c0, "NSG Missing on Subnet prod-data", "medium",
     None, None, "vnet-acme-prod/prod-data", "Virtual Network",
     "Attach a Network Security Group to restrict inbound traffic."),
    # NHS Healthcare - vulnerability scan
    (scan_ids[5], c2, "Log4Shell RCE Vulnerability (CVE-2021-44228)", "critical",
     "CVE-2021-44228", 10.0, "nhs-api-server-03", "Application Server",
     "Update log4j to 2.17.1 or mitigate with JVM flag -Dlog4j2.formatMsgNoLookups=true."),
    (scan_ids[5], c2, "PHI Data Stored in Unencrypted Blob Container", "critical",
     None, None, "nhsphi-backup-storage", "Storage Account",
     "Enable encryption at rest and move PHI to encrypted containers with private access only."),
    (scan_ids[5], c2, "Patient Database Accessible from Public Internet", "critical",
     None, None, "nhs-sql-prod", "SQL Server",
     "Remove public endpoint; configure Private Link and restrict firewall rules."),
    (scan_ids[5], c2, "Service Account with Excessive Privileges", "high",
     None, None, "svc-nhs-integration@nhs.local", "Service Account",
     "Apply least-privilege principle; remove owner-level Azure role assignments."),
    (scan_ids[5], c2, "Missing RBAC on FHIR API Endpoints", "high",
     None, None, "nhs-fhir-api", "API Management",
     "Implement RBAC using Azure AD groups and scoped API policies."),
    # TechCorp - full scan
    (scan_ids[3], c1, "Hardcoded AWS Access Keys in GitHub Repository", "critical",
     None, None, "github.com/techcorp/infrastructure", "Source Code",
     "Rotate keys immediately. Use IAM roles or AWS Secrets Manager instead."),
    (scan_ids[3], c1, "S3 Bucket Public Read Access Enabled", "high",
     None, None, "techcorp-assets-prod", "S3 Bucket",
     "Set bucket ACL to private; use pre-signed URLs for public content."),
    (scan_ids[3], c1, "EC2 Instances Running as Root", "high",
     None, None, "i-0a1b2c3d4e5f", "EC2 Instance",
     "Configure EC2 instances to run application workloads as non-root users."),
    (scan_ids[3], c1, "CloudTrail Logging Disabled in us-west-2", "medium",
     None, None, "AWS/us-west-2", "CloudTrail",
     "Enable CloudTrail in all regions and ship logs to central S3 bucket."),
]

for f in findings_raw:
    scan_id, client_id, title, severity, cve, cvss, resource_id, resource_type, remediation = f
    cur.execute("""
        INSERT INTO findings (id, scan_id, title, severity, cve_id, cvss_score,
                              resource_id, resource_type, status, remediation,
                              evidence, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, '{}', ?)
    """, (_uuid(), scan_id, title, severity, cve, cvss, resource_id, resource_type,
          remediation, dt(days_ago=5)))

# ── Risks ────────────────────────────────────────────────────────────────────
risks_raw = [
    (c0, "Ransomware Attack on Financial Systems", "critical", 4, 5, 20.0, "Cyber Threat",
     "Block lateral movement via microsegmentation; deploy EDR on all endpoints; test offline backups monthly."),
    (c0, "Regulatory Non-Compliance with FCA Cyber Rules", "high", 3, 4, 12.0, "Compliance",
     "Complete gap assessment against PS21/3; appoint CISO; complete NIST CSF assessment by Q3."),
    (c0, "Privileged Account Compromise", "high", 3, 5, 15.0, "Identity",
     "Enforce MFA and PAM solution for all privileged accounts; review admin access quarterly."),
    (c1, "Data Breach via Exposed AWS Credentials", "critical", 5, 5, 25.0, "Cloud Security",
     "Implement secrets scanning in CI/CD pipelines; rotate all exposed keys; enable GuardDuty."),
    (c1, "Supply Chain Attack through Third-Party Dependencies", "high", 3, 4, 12.0, "Supply Chain",
     "Implement SCA tooling (Dependabot); pin dependency versions; conduct vendor security reviews."),
    (c2, "Patient Data Breach (GDPR Article 83)", "critical", 4, 5, 20.0, "Data Privacy",
     "Encrypt all PHI at rest and in transit; implement DLP controls; conduct DPIA for new processing activities."),
    (c2, "HIPAA Non-Compliance Audit Finding", "high", 3, 4, 12.0, "Compliance",
     "Implement access logging for all PHI access; conduct annual security training; complete BAA with all vendors."),
    (c2, "Critical Vulnerability Exploitation (Log4Shell)", "critical", 5, 5, 25.0, "Vulnerability",
     "Patch Log4j immediately; conduct full asset inventory; implement virtual patching via WAF."),
    (c3, "PCI DSS Non-Compliance (Cardholder Data)", "high", 4, 5, 20.0, "Compliance",
     "Scope reduction: move card processing to third-party PCI-compliant provider; complete SAQ-D by Q2."),
    (c3, "Container Escape in Production Kubernetes", "medium", 2, 4, 8.0, "Infrastructure",
     "Update container runtime; implement Pod Security Standards; restrict privileged container usage."),
]

for r in risks_raw:
    client_id, title, level, likelihood, impact, score, category, plan = r
    cur.execute("""
        INSERT INTO risks (id, client_id, title, risk_level, likelihood, impact, risk_score,
                           category, status, mitigation_plan, owner, finding_ids, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, 'Security Team', '[]', ?)
    """, (_uuid(), client_id, title, level, likelihood, impact, score, category, plan, dt(days_ago=7)))

# ── Framework Assessments ────────────────────────────────────────────────────
assessments = [
    (c0, "nist_csf", scan_ids[2], 71.4, 98, 72, 26, 0),
    (c0, "iso_27001", None, 63.2, 114, 72, 42, 0),
    (c1, "cis_v8", scan_ids[4], 84.1, 113, 95, 18, 0),
    (c1, "nist_800_53", None, 68.7, 164, 113, 51, 0),
    (c2, "gdpr", scan_ids[6], 57.1, 77, 44, 33, 0),
    (c2, "nist_csf", None, 52.8, 98, 52, 46, 0),
    (c2, "iso_27001", None, 61.0, 114, 70, 44, 0),
    (c3, "pci_dss", None, 44.2, 86, 38, 48, 0),
    (c3, "cis_v8", None, 69.1, 113, 78, 35, 0),
]

for a in assessments:
    client_id, framework, scan_id, score, total, passed, failed, partial = a
    cur.execute("""
        INSERT INTO framework_assessments (id, client_id, framework, scan_id, overall_score,
                                           controls_total, controls_passed, controls_failed,
                                           controls_partial, control_results, assessed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?)
    """, (_uuid(), client_id, framework, scan_id, score, total, passed, failed, partial, dt(days_ago=3)))

conn.commit()
conn.close()

print("Seed complete!")
print(f"  {len(clients)} clients")
print(f"  {len(connectors)} connectors")
print(f"  {len(scans)} scans")
print(f"  {len(findings_raw)} findings")
print(f"  {len(risks_raw)} risks")
print(f"  {len(assessments)} framework assessments")
