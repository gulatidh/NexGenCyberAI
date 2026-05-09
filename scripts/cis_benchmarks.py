"""
CIS Benchmark control catalogs.

Each entry is a tuple: (control_id, parent_id_or_None, domain, title).
Sections (top-level grouping) carry parent=None, weight=0.
Leaf controls reference their section as parent and have weight=1.

CIS Benchmarks are licensed for non-commercial reference. We reproduce only
the canonical control numbering and short titles (factual reference data
widely cited in vendor compliance tooling). Detailed audit/remediation
guidance must be consulted at https://www.cisecurity.org/benchmark.

For the OS/network/app benchmarks (which have hundreds of leaf controls),
only the section structure is included. Use the
POST /api/v1/frameworks/{framework}/import endpoint to upload a CSV/JSON
generated from the official CIS XLSX export to populate leaf controls.
"""
from typing import Any, Dict, List, Tuple

# A "control row" tuple: (control_id, parent_id, domain, title, weight)
# weight=0 → grouping header (function/section/family); weight=1 → leaf control


def _section(control_id: str, title: str) -> Tuple[str, None, str, str, int]:
    return (control_id, None, title, title, 0)


def _ctrl(control_id: str, parent: str, domain: str, title: str) -> Tuple[str, str, str, str, int]:
    return (control_id, parent, domain, title, 1)


# ── CIS Microsoft Azure Foundations Benchmark 5.0.0 ───────────────────────────

CIS_AZURE = {
    "framework": "cis_azure",
    "version": "5.0.0",
    "source": "https://www.cisecurity.org/benchmark/azure",
    "rows": [
        _section("1", "Identity and Access Management"),
        _ctrl("1.1.1", "1", "Identity and Access Management", "Ensure Security Defaults is enabled on Azure Active Directory"),
        _ctrl("1.1.2", "1", "Identity and Access Management", "Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users"),
        _ctrl("1.1.3", "1", "Identity and Access Management", "Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users"),
        _ctrl("1.1.4", "1", "Identity and Access Management", "Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled"),
        _ctrl("1.2.1", "1", "Identity and Access Management", "Ensure Trusted Locations Are Defined"),
        _ctrl("1.2.2", "1", "Identity and Access Management", "Ensure that an exclusionary Geographic Access Policy is considered"),
        _ctrl("1.2.3", "1", "Identity and Access Management", "Ensure that A Multi-factor Authentication Policy Exists for All Users"),
        _ctrl("1.2.4", "1", "Identity and Access Management", "Ensure Multi-factor Authentication is Required for Risky Sign-ins"),
        _ctrl("1.2.5", "1", "Identity and Access Management", "Ensure Multi-factor Authentication is Required for Azure Management"),
        _ctrl("1.3", "1", "Identity and Access Management", "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'"),
        _ctrl("1.4", "1", "Identity and Access Management", "Ensure Guest Users Are Reviewed on a Regular Basis"),
        _ctrl("1.5", "1", "Identity and Access Management", "Ensure That 'Number of methods required to reset' is set to '2'"),
        _ctrl("1.6", "1", "Identity and Access Management", "Ensure that account 'Lockout Threshold' is less than or equal to '10'"),
        _ctrl("1.7", "1", "Identity and Access Management", "Ensure that account 'Lockout duration in seconds' is greater than or equal to '60'"),
        _ctrl("1.8", "1", "Identity and Access Management", "Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to '0'"),
        _ctrl("1.9", "1", "Identity and Access Management", "Ensure that 'Notify users on password resets?' is set to 'Yes'"),
        _ctrl("1.10", "1", "Identity and Access Management", "Ensure that 'Notify all admins when other admins reset their password?' is set to 'Yes'"),
        _ctrl("1.11", "1", "Identity and Access Management", "Ensure 'User consent for applications' is set to 'Do not allow user consent'"),
        _ctrl("1.12", "1", "Identity and Access Management", "Ensure 'User consent for applications' Is Set To 'Allow for Verified Publishers'"),
        _ctrl("1.13", "1", "Identity and Access Management", "Ensure that 'Users can add gallery apps to My Apps' is set to 'No'"),
        _ctrl("1.14", "1", "Identity and Access Management", "Ensure That 'Users Can Register Applications' Is Set to 'No'"),
        _ctrl("1.15", "1", "Identity and Access Management", "Ensure That 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects'"),
        _ctrl("1.16", "1", "Identity and Access Management", "Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles can invite guest users'"),
        _ctrl("1.17", "1", "Identity and Access Management", "Ensure That 'Restrict access to Microsoft Entra admin center' is Set to 'Yes'"),
        _ctrl("1.18", "1", "Identity and Access Management", "Ensure that 'Restrict user ability to access groups features in My Groups' is set to 'Yes'"),
        _ctrl("1.19", "1", "Identity and Access Management", "Ensure that 'Users can create security groups in Azure portals, API or PowerShell' is set to 'No'"),
        _ctrl("1.20", "1", "Identity and Access Management", "Ensure that 'Owners can manage group membership requests in My Groups' is set to 'No'"),
        _ctrl("1.21", "1", "Identity and Access Management", "Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'"),
        _ctrl("1.22", "1", "Identity and Access Management", "Ensure that 'Require Multi-Factor Authentication to register or join devices with Microsoft Entra' is set to 'Yes'"),
        _ctrl("1.23", "1", "Identity and Access Management", "Ensure That No Custom Subscription Administrator Roles Exist"),
        _ctrl("1.24", "1", "Identity and Access Management", "Ensure a Custom Role is Assigned Permissions for Administering Resource Locks"),
        _ctrl("1.25", "1", "Identity and Access Management", "Ensure That 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering Microsoft Entra tenant' Is Set To 'Permit no one'"),

        _section("2", "Microsoft Defender for Cloud"),
        _ctrl("2.1.1", "2", "Microsoft Defender for Cloud", "Ensure That 'Defender plan' is set to 'On' for Servers"),
        _ctrl("2.1.2", "2", "Microsoft Defender for Cloud", "Ensure That 'Defender plan' is set to 'On' for App Service"),
        _ctrl("2.1.3", "2", "Microsoft Defender for Cloud", "Ensure That 'Defender plan' is set to 'On' for Databases"),
        _ctrl("2.1.4", "2", "Microsoft Defender for Cloud", "Ensure That 'Defender plan' is set to 'On' for SQL Servers on Machines"),
        _ctrl("2.1.5", "2", "Microsoft Defender for Cloud", "Ensure That 'Defender plan' is set to 'On' for Open-Source Relational Databases"),
        _ctrl("2.1.6", "2", "Microsoft Defender for Cloud", "Ensure That 'Defender plan' is set to 'On' for Storage"),
        _ctrl("2.1.7", "2", "Microsoft Defender for Cloud", "Ensure That 'Defender plan' is set to 'On' for Containers"),
        _ctrl("2.1.8", "2", "Microsoft Defender for Cloud", "Ensure That 'Defender plan' is set to 'On' for Key Vault"),
        _ctrl("2.1.9", "2", "Microsoft Defender for Cloud", "Ensure That 'Defender plan' is set to 'On' for Resource Manager"),
        _ctrl("2.1.10", "2", "Microsoft Defender for Cloud", "Ensure that Microsoft Defender for Cloud Apps integration is enabled"),
        _ctrl("2.1.11", "2", "Microsoft Defender for Cloud", "Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'"),
        _ctrl("2.1.12", "2", "Microsoft Defender for Cloud", "Ensure that Auto provisioning of 'Vulnerability assessment for machines' is set to 'On'"),
        _ctrl("2.1.13", "2", "Microsoft Defender for Cloud", "Ensure that 'All users with the following roles' is set to 'Owner'"),
        _ctrl("2.1.14", "2", "Microsoft Defender for Cloud", "Ensure 'Additional email addresses' is configured with a security contact email"),
        _ctrl("2.1.15", "2", "Microsoft Defender for Cloud", "Ensure That 'Notify about alerts with the following severity' is Set to 'High'"),

        _section("3", "Storage Accounts"),
        _ctrl("3.1", "3", "Storage Accounts", "Ensure that 'Secure transfer required' is set to 'Enabled'"),
        _ctrl("3.2", "3", "Storage Accounts", "Ensure that 'Enable Infrastructure Encryption' for Each Storage Account in Azure Storage is Set to 'enabled'"),
        _ctrl("3.3", "3", "Storage Accounts", "Ensure That Storage Account Access Keys are Periodically Regenerated"),
        _ctrl("3.4", "3", "Storage Accounts", "Ensure that Shared Access Signature Tokens Expire Within an Hour"),
        _ctrl("3.5", "3", "Storage Accounts", "Ensure that 'Public access level' is disabled for storage accounts with blob containers"),
        _ctrl("3.6", "3", "Storage Accounts", "Ensure Default Network Access Rule for Storage Accounts is Set to Deny"),
        _ctrl("3.7", "3", "Storage Accounts", "Ensure 'Trusted Microsoft Services' is Enabled for Storage Account Access"),
        _ctrl("3.8", "3", "Storage Accounts", "Ensure Soft Delete is Enabled for Azure Containers and Blob Storage"),
        _ctrl("3.9", "3", "Storage Accounts", "Ensure Storage for Critical Data are Encrypted with Customer Managed Keys (CMK)"),
        _ctrl("3.10", "3", "Storage Accounts", "Ensure Storage logging is Enabled for Queue Service for 'Read', 'Write', and 'Delete' requests"),
        _ctrl("3.11", "3", "Storage Accounts", "Ensure Storage logging is Enabled for Blob Service for 'Read', 'Write', and 'Delete' requests"),
        _ctrl("3.12", "3", "Storage Accounts", "Ensure Storage logging is Enabled for Table Service for 'Read', 'Write', and 'Delete' requests"),
        _ctrl("3.13", "3", "Storage Accounts", "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'"),
        _ctrl("3.14", "3", "Storage Accounts", "Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled"),
        _ctrl("3.15", "3", "Storage Accounts", "Ensure Private Endpoints are used to access Storage Accounts"),

        _section("4", "Database Services"),
        _ctrl("4.1.1", "4", "Database Services", "Ensure that 'Auditing' is set to 'On' for SQL Servers"),
        _ctrl("4.1.2", "4", "Database Services", "Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)"),
        _ctrl("4.1.3", "4", "Database Services", "Ensure SQL server's Transparent Data Encryption (TDE) protector is encrypted with Customer-managed key"),
        _ctrl("4.1.4", "4", "Database Services", "Ensure that Microsoft Entra authentication is Configured for SQL Servers"),
        _ctrl("4.1.5", "4", "Database Services", "Ensure that 'Data encryption' is set to 'On' on a SQL Database"),
        _ctrl("4.1.6", "4", "Database Services", "Ensure that 'Auditing' Retention is 'greater than 90 days'"),
        _ctrl("4.2.1", "4", "Database Services", "Ensure that Advanced Threat Protection (ATP) on a SQL server is set to 'Enabled'"),
        _ctrl("4.2.2", "4", "Database Services", "Ensure that Vulnerability Assessment (VA) is enabled on a SQL server"),
        _ctrl("4.2.3", "4", "Database Services", "Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server"),
        _ctrl("4.2.4", "4", "Database Services", "Ensure that VA setting Send scan reports to is configured for a SQL server"),
        _ctrl("4.2.5", "4", "Database Services", "Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server"),
        _ctrl("4.3.1", "4", "Database Services", "Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server"),
        _ctrl("4.3.2", "4", "Database Services", "Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server"),
        _ctrl("4.3.3", "4", "Database Services", "Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server"),
        _ctrl("4.3.4", "4", "Database Services", "Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server"),
        _ctrl("4.3.5", "4", "Database Services", "Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server"),
        _ctrl("4.3.6", "4", "Database Services", "Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server"),
        _ctrl("4.3.7", "4", "Database Services", "Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled"),
        _ctrl("4.3.8", "4", "Database Services", "Ensure 'Infrastructure double encryption' for PostgreSQL Database Server is 'Enabled'"),
        _ctrl("4.4.1", "4", "Database Services", "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server"),
        _ctrl("4.4.2", "4", "Database Services", "Ensure 'TLS Version' is set to 'TLSV1.2' (or higher) for MySQL flexible Database Server"),

        _section("5", "Logging and Monitoring"),
        _ctrl("5.1.1", "5", "Logging and Monitoring", "Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs"),
        _ctrl("5.1.2", "5", "Logging and Monitoring", "Ensure Diagnostic Setting captures appropriate categories"),
        _ctrl("5.1.3", "5", "Logging and Monitoring", "Ensure the Storage Container Storing the Activity Logs is not Publicly Accessible"),
        _ctrl("5.1.4", "5", "Logging and Monitoring", "Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key"),
        _ctrl("5.1.5", "5", "Logging and Monitoring", "Ensure that logging for Azure Key Vault is 'Enabled'"),
        _ctrl("5.2.1", "5", "Logging and Monitoring", "Ensure that Activity Log Alert exists for Create Policy Assignment"),
        _ctrl("5.2.2", "5", "Logging and Monitoring", "Ensure that Activity Log Alert exists for Delete Policy Assignment"),
        _ctrl("5.2.3", "5", "Logging and Monitoring", "Ensure that Activity Log Alert exists for Create or Update Network Security Group"),
        _ctrl("5.2.4", "5", "Logging and Monitoring", "Ensure that Activity Log Alert exists for Delete Network Security Group"),
        _ctrl("5.2.5", "5", "Logging and Monitoring", "Ensure that Activity Log Alert exists for Create or Update Solution"),
        _ctrl("5.2.6", "5", "Logging and Monitoring", "Ensure that Activity Log Alert exists for Delete Solution"),
        _ctrl("5.2.7", "5", "Logging and Monitoring", "Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule"),
        _ctrl("5.2.8", "5", "Logging and Monitoring", "Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule"),
        _ctrl("5.2.9", "5", "Logging and Monitoring", "Ensure that Activity Log Alert exists for Create or Update Public IP Address rule"),
        _ctrl("5.2.10", "5", "Logging and Monitoring", "Ensure that Activity Log Alert exists for Delete Public IP Address rule"),
        _ctrl("5.3", "5", "Logging and Monitoring", "Ensure that Diagnostic Logs Are Enabled for All Services that Support it"),

        _section("6", "Networking"),
        _ctrl("6.1", "6", "Networking", "Ensure that RDP access from the Internet is evaluated and restricted"),
        _ctrl("6.2", "6", "Networking", "Ensure that SSH access from the Internet is evaluated and restricted"),
        _ctrl("6.3", "6", "Networking", "Ensure that UDP access from the Internet is evaluated and restricted"),
        _ctrl("6.4", "6", "Networking", "Ensure that HTTP(S) access from the Internet is evaluated and restricted"),
        _ctrl("6.5", "6", "Networking", "Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'"),
        _ctrl("6.6", "6", "Networking", "Ensure that Network Watcher is 'Enabled' for Azure Regions that are in use"),
        _ctrl("6.7", "6", "Networking", "Ensure that Public IP addresses are Evaluated on a Periodic Basis"),

        _section("7", "Virtual Machines"),
        _ctrl("7.1", "7", "Virtual Machines", "Ensure an Azure Bastion Host Exists"),
        _ctrl("7.2", "7", "Virtual Machines", "Ensure Virtual Machines are utilizing Managed Disks"),
        _ctrl("7.3", "7", "Virtual Machines", "Ensure that 'OS and Data' disks are encrypted with Customer Managed Key (CMK)"),
        _ctrl("7.4", "7", "Virtual Machines", "Ensure that 'Unattached disks' are encrypted with 'Customer Managed Key' (CMK)"),
        _ctrl("7.5", "7", "Virtual Machines", "Ensure that Only Approved Extensions Are Installed"),
        _ctrl("7.6", "7", "Virtual Machines", "Ensure that Endpoint Protection for all Virtual Machines is installed"),
        _ctrl("7.7", "7", "Virtual Machines", "Ensure that VHDs are Encrypted"),
        _ctrl("7.8", "7", "Virtual Machines", "Ensure trusted launch is enabled on Virtual Machines"),

        _section("8", "Key Vault"),
        _ctrl("8.1", "8", "Key Vault", "Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults"),
        _ctrl("8.2", "8", "Key Vault", "Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults"),
        _ctrl("8.3", "8", "Key Vault", "Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults"),
        _ctrl("8.4", "8", "Key Vault", "Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults"),
        _ctrl("8.5", "8", "Key Vault", "Ensure the Key Vault is Recoverable (Soft Delete + Purge Protection)"),
        _ctrl("8.6", "8", "Key Vault", "Enable Role Based Access Control for Azure Key Vault"),
        _ctrl("8.7", "8", "Key Vault", "Ensure that Private Endpoints are Used for Azure Key Vault"),
        _ctrl("8.8", "8", "Key Vault", "Ensure Automatic Key Rotation is Enabled Within Azure Key Vault for the Supported Services"),

        _section("9", "App Service"),
        _ctrl("9.1", "9", "App Service", "Ensure 'HTTPS Only' is set to 'On'"),
        _ctrl("9.2", "9", "App Service", "Ensure App Service Authentication is set up for apps in Azure App Service"),
        _ctrl("9.3", "9", "App Service", "Ensure 'FTP State' is set to 'FTPS Only' or 'Disabled'"),
        _ctrl("9.4", "9", "App Service", "Ensure Web App is using the latest version of TLS encryption"),
        _ctrl("9.5", "9", "App Service", "Ensure that Register with Microsoft Entra is enabled on App Service"),
        _ctrl("9.6", "9", "App Service", "Ensure That 'PHP version' is the Latest, If Used to Run the Web App"),
        _ctrl("9.7", "9", "App Service", "Ensure That 'Python version' is the Latest Stable Version, If Used to Run the Web App"),
        _ctrl("9.8", "9", "App Service", "Ensure That 'Java version' is the Latest, If Used to Run the Web App"),
        _ctrl("9.9", "9", "App Service", "Ensure That 'HTTP Version' is the Latest, If Used to Run the Web App"),
        _ctrl("9.10", "9", "App Service", "Ensure FTP deployments are Disabled"),
        _ctrl("9.11", "9", "App Service", "Ensure Azure Key Vaults are Used to Store Secrets"),

        _section("10", "Miscellaneous"),
        _ctrl("10.1", "10", "Miscellaneous", "Ensure that Resource Locks are set for Mission-Critical Azure Resources"),
    ],
}


# ── CIS Amazon Web Services Foundations 7.0.0 ─────────────────────────────────

CIS_AWS = {
    "framework": "cis_aws",
    "version": "7.0.0",
    "source": "https://www.cisecurity.org/benchmark/amazon_web_services",
    "rows": [
        _section("1", "Identity and Access Management"),
        _ctrl("1.1", "1", "Identity and Access Management", "Maintain current contact details"),
        _ctrl("1.2", "1", "Identity and Access Management", "Ensure security contact information is registered"),
        _ctrl("1.3", "1", "Identity and Access Management", "Ensure security questions are registered in the AWS account"),
        _ctrl("1.4", "1", "Identity and Access Management", "Ensure no 'root' user account access key exists"),
        _ctrl("1.5", "1", "Identity and Access Management", "Ensure MFA is enabled for the 'root' user account"),
        _ctrl("1.6", "1", "Identity and Access Management", "Ensure hardware MFA is enabled for the 'root' user account"),
        _ctrl("1.7", "1", "Identity and Access Management", "Eliminate use of the 'root' user for administrative and daily tasks"),
        _ctrl("1.8", "1", "Identity and Access Management", "Ensure IAM password policy requires minimum length of 14 or greater"),
        _ctrl("1.9", "1", "Identity and Access Management", "Ensure IAM password policy prevents password reuse"),
        _ctrl("1.10", "1", "Identity and Access Management", "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password"),
        _ctrl("1.11", "1", "Identity and Access Management", "Do not setup access keys during initial user setup for all IAM users that have a console password"),
        _ctrl("1.12", "1", "Identity and Access Management", "Ensure credentials unused for 45 days or greater are disabled"),
        _ctrl("1.13", "1", "Identity and Access Management", "Ensure there is only one active access key available for any single IAM user"),
        _ctrl("1.14", "1", "Identity and Access Management", "Ensure access keys are rotated every 90 days or less"),
        _ctrl("1.15", "1", "Identity and Access Management", "Ensure IAM Users Receive Permissions Only Through Groups"),
        _ctrl("1.16", "1", "Identity and Access Management", "Ensure IAM policies that allow full \"*:*\" administrative privileges are not attached"),
        _ctrl("1.17", "1", "Identity and Access Management", "Ensure a support role has been created to manage incidents with AWS Support"),
        _ctrl("1.18", "1", "Identity and Access Management", "Ensure IAM instance roles are used for AWS resource access from instances"),
        _ctrl("1.19", "1", "Identity and Access Management", "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed"),
        _ctrl("1.20", "1", "Identity and Access Management", "Ensure that IAM Access analyzer is enabled for all regions"),
        _ctrl("1.21", "1", "Identity and Access Management", "Ensure IAM users are managed centrally via identity federation or AWS Organizations"),
        _ctrl("1.22", "1", "Identity and Access Management", "Ensure access to AWSCloudShellFullAccess is restricted"),

        _section("2", "Storage"),
        _ctrl("2.1.1", "2", "Storage", "Ensure S3 Bucket Policy is set to deny HTTP requests"),
        _ctrl("2.1.2", "2", "Storage", "Ensure MFA Delete is enabled on S3 buckets"),
        _ctrl("2.1.3", "2", "Storage", "Ensure all data in Amazon S3 has been discovered, classified, and secured when required"),
        _ctrl("2.1.4", "2", "Storage", "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'"),
        _ctrl("2.1.5", "2", "Storage", "Ensure that S3 Buckets enable Server-Side Encryption by default"),
        _ctrl("2.2.1", "2", "Storage", "Ensure EBS Volume Encryption is Enabled in all Regions"),
        _ctrl("2.3.1", "2", "Storage", "Ensure that encryption is enabled for RDS Instances"),
        _ctrl("2.3.2", "2", "Storage", "Ensure auto minor version upgrades are enabled for RDS instances"),
        _ctrl("2.3.3", "2", "Storage", "Ensure that public access is not given to RDS Instance"),
        _ctrl("2.4.1", "2", "Storage", "Ensure that encryption is enabled for EFS file systems"),

        _section("3", "Logging"),
        _ctrl("3.1", "3", "Logging", "Ensure CloudTrail is enabled in all regions"),
        _ctrl("3.2", "3", "Logging", "Ensure CloudTrail log file validation is enabled"),
        _ctrl("3.3", "3", "Logging", "Ensure AWS Config is enabled in all regions"),
        _ctrl("3.4", "3", "Logging", "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"),
        _ctrl("3.5", "3", "Logging", "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"),
        _ctrl("3.6", "3", "Logging", "Ensure rotation for customer-created symmetric CMKs is enabled"),
        _ctrl("3.7", "3", "Logging", "Ensure VPC flow logging is enabled in all VPCs"),
        _ctrl("3.8", "3", "Logging", "Ensure that Object-level logging for write events is enabled for S3 bucket"),
        _ctrl("3.9", "3", "Logging", "Ensure that Object-level logging for read events is enabled for S3 bucket"),

        _section("4", "Monitoring"),
        _ctrl("4.1", "4", "Monitoring", "Ensure unauthorized API calls are monitored"),
        _ctrl("4.2", "4", "Monitoring", "Ensure management console sign-in without MFA is monitored"),
        _ctrl("4.3", "4", "Monitoring", "Ensure usage of 'root' account is monitored"),
        _ctrl("4.4", "4", "Monitoring", "Ensure IAM policy changes are monitored"),
        _ctrl("4.5", "4", "Monitoring", "Ensure CloudTrail configuration changes are monitored"),
        _ctrl("4.6", "4", "Monitoring", "Ensure AWS Management Console authentication failures are monitored"),
        _ctrl("4.7", "4", "Monitoring", "Ensure disabling or scheduled deletion of customer created CMKs is monitored"),
        _ctrl("4.8", "4", "Monitoring", "Ensure S3 bucket policy changes are monitored"),
        _ctrl("4.9", "4", "Monitoring", "Ensure AWS Config configuration changes are monitored"),
        _ctrl("4.10", "4", "Monitoring", "Ensure security group changes are monitored"),
        _ctrl("4.11", "4", "Monitoring", "Ensure Network Access Control List (NACL) changes are monitored"),
        _ctrl("4.12", "4", "Monitoring", "Ensure changes to network gateways are monitored"),
        _ctrl("4.13", "4", "Monitoring", "Ensure route table changes are monitored"),
        _ctrl("4.14", "4", "Monitoring", "Ensure VPC changes are monitored"),
        _ctrl("4.15", "4", "Monitoring", "Ensure AWS Organizations changes are monitored"),
        _ctrl("4.16", "4", "Monitoring", "Ensure AWS Security Hub is enabled"),

        _section("5", "Networking"),
        _ctrl("5.1", "5", "Networking", "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports"),
        _ctrl("5.2", "5", "Networking", "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports"),
        _ctrl("5.3", "5", "Networking", "Ensure no security groups allow ingress from ::/0 to remote server administration ports"),
        _ctrl("5.4", "5", "Networking", "Ensure the default security group of every VPC restricts all traffic"),
        _ctrl("5.5", "5", "Networking", "Ensure routing tables for VPC peering are 'least access'"),
        _ctrl("5.6", "5", "Networking", "Ensure that EC2 Metadata Service only allows IMDSv2"),
    ],
}


# ── CIS AWS Database Services 2.0.0 ───────────────────────────────────────────

CIS_AWS_DB = {
    "framework": "cis_aws_db",
    "version": "2.0.0",
    "source": "https://www.cisecurity.org/benchmark/amazon_web_services",
    "rows": [
        _section("1", "Amazon Aurora / RDS"),
        _ctrl("1.1", "1", "Amazon Aurora / RDS", "Ensure RDS encryption-at-rest is enabled"),
        _ctrl("1.2", "1", "Amazon Aurora / RDS", "Ensure RDS instances are not publicly accessible"),
        _ctrl("1.3", "1", "Amazon Aurora / RDS", "Ensure RDS automated backups are enabled"),
        _ctrl("1.4", "1", "Amazon Aurora / RDS", "Ensure RDS backup retention is 7+ days"),
        _ctrl("1.5", "1", "Amazon Aurora / RDS", "Ensure RDS minor version auto-upgrade is enabled"),
        _ctrl("1.6", "1", "Amazon Aurora / RDS", "Ensure RDS Multi-AZ is enabled for production workloads"),
        _ctrl("1.7", "1", "Amazon Aurora / RDS", "Ensure RDS deletion protection is enabled"),
        _ctrl("1.8", "1", "Amazon Aurora / RDS", "Ensure RDS Performance Insights is enabled"),
        _ctrl("1.9", "1", "Amazon Aurora / RDS", "Ensure IAM database authentication is enabled where supported"),
        _ctrl("1.10", "1", "Amazon Aurora / RDS", "Ensure RDS Audit Logs are exported to CloudWatch"),
        _ctrl("1.11", "1", "Amazon Aurora / RDS", "Ensure RDS instances use KMS CMKs (not AWS-managed default keys) for encryption"),

        _section("2", "Amazon DynamoDB"),
        _ctrl("2.1", "2", "Amazon DynamoDB", "Ensure DynamoDB encryption-at-rest is enabled with KMS CMK"),
        _ctrl("2.2", "2", "Amazon DynamoDB", "Ensure DynamoDB Point-in-Time Recovery is enabled"),
        _ctrl("2.3", "2", "Amazon DynamoDB", "Ensure DynamoDB tables are not publicly accessible via VPC endpoint policy"),
        _ctrl("2.4", "2", "Amazon DynamoDB", "Ensure DynamoDB streams are encrypted"),
        _ctrl("2.5", "2", "Amazon DynamoDB", "Ensure DynamoDB Continuous Backups are enabled"),

        _section("3", "Amazon DocumentDB"),
        _ctrl("3.1", "3", "Amazon DocumentDB", "Ensure DocumentDB encryption-at-rest is enabled"),
        _ctrl("3.2", "3", "Amazon DocumentDB", "Ensure DocumentDB audit logging is enabled"),
        _ctrl("3.3", "3", "Amazon DocumentDB", "Ensure DocumentDB cluster is not publicly accessible"),
        _ctrl("3.4", "3", "Amazon DocumentDB", "Ensure DocumentDB has automated snapshots enabled"),

        _section("4", "Amazon Redshift"),
        _ctrl("4.1", "4", "Amazon Redshift", "Ensure Redshift cluster encryption is enabled"),
        _ctrl("4.2", "4", "Amazon Redshift", "Ensure Redshift cluster is not publicly accessible"),
        _ctrl("4.3", "4", "Amazon Redshift", "Ensure Redshift audit logging is enabled"),
        _ctrl("4.4", "4", "Amazon Redshift", "Ensure Redshift automated snapshots are enabled with retention >= 7 days"),
        _ctrl("4.5", "4", "Amazon Redshift", "Ensure Redshift requires SSL connections"),
        _ctrl("4.6", "4", "Amazon Redshift", "Ensure Redshift uses VPC enhanced routing"),

        _section("5", "Amazon ElastiCache"),
        _ctrl("5.1", "5", "Amazon ElastiCache", "Ensure ElastiCache for Redis encryption-at-rest is enabled"),
        _ctrl("5.2", "5", "Amazon ElastiCache", "Ensure ElastiCache for Redis encryption-in-transit is enabled"),
        _ctrl("5.3", "5", "Amazon ElastiCache", "Ensure ElastiCache for Redis AUTH token is set"),
        _ctrl("5.4", "5", "Amazon ElastiCache", "Ensure ElastiCache automatic failover is enabled"),
        _ctrl("5.5", "5", "Amazon ElastiCache", "Ensure ElastiCache automatic backups are enabled"),

        _section("6", "Amazon Neptune"),
        _ctrl("6.1", "6", "Amazon Neptune", "Ensure Neptune encryption-at-rest is enabled"),
        _ctrl("6.2", "6", "Amazon Neptune", "Ensure Neptune cluster is not publicly accessible"),
        _ctrl("6.3", "6", "Amazon Neptune", "Ensure Neptune IAM authentication is enabled"),
        _ctrl("6.4", "6", "Amazon Neptune", "Ensure Neptune audit logging is exported to CloudWatch"),

        _section("7", "Amazon Timestream"),
        _ctrl("7.1", "7", "Amazon Timestream", "Ensure Timestream tables use customer-managed KMS keys"),
        _ctrl("7.2", "7", "Amazon Timestream", "Ensure Timestream magnetic store writes are configured with appropriate retention"),
    ],
}


# ── CIS Alibaba Cloud Foundation 2.0.0 ────────────────────────────────────────

CIS_ALIBABA = {
    "framework": "cis_alibaba",
    "version": "2.0.0",
    "source": "https://www.cisecurity.org/benchmark/alibaba_cloud",
    "rows": [
        _section("1", "Identity and Access Management"),
        _ctrl("1.1", "1", "Identity and Access Management", "Ensure RAM password policy requires minimum length of 14 or greater"),
        _ctrl("1.2", "1", "Identity and Access Management", "Ensure RAM password policy prevents password reuse"),
        _ctrl("1.3", "1", "Identity and Access Management", "Ensure RAM password policy expires passwords within 90 days or less"),
        _ctrl("1.4", "1", "Identity and Access Management", "Ensure no root account access keys exist"),
        _ctrl("1.5", "1", "Identity and Access Management", "Ensure MFA is enabled for the root account"),
        _ctrl("1.6", "1", "Identity and Access Management", "Ensure MFA is enabled for all RAM users with console access"),
        _ctrl("1.7", "1", "Identity and Access Management", "Ensure RAM access keys are rotated every 90 days or less"),
        _ctrl("1.8", "1", "Identity and Access Management", "Ensure unused RAM credentials are disabled after 45 days"),
        _ctrl("1.9", "1", "Identity and Access Management", "Ensure RAM users receive permissions only through groups"),
        _ctrl("1.10", "1", "Identity and Access Management", "Ensure no inline RAM policies attach administrator privileges"),
        _ctrl("1.11", "1", "Identity and Access Management", "Ensure a support role has been created"),

        _section("2", "Logging"),
        _ctrl("2.1", "2", "Logging", "Ensure ActionTrail is enabled for all regions"),
        _ctrl("2.2", "2", "Logging", "Ensure ActionTrail logs are written to an OSS bucket with versioning + lifecycle"),
        _ctrl("2.3", "2", "Logging", "Ensure ActionTrail integrates with Log Service"),
        _ctrl("2.4", "2", "Logging", "Ensure ActionTrail OSS bucket access logging is enabled"),

        _section("3", "Monitoring"),
        _ctrl("3.1", "3", "Monitoring", "Ensure CloudMonitor alerts on RAM policy changes"),
        _ctrl("3.2", "3", "Monitoring", "Ensure CloudMonitor alerts on Security Group changes"),
        _ctrl("3.3", "3", "Monitoring", "Ensure CloudMonitor alerts on Network ACL changes"),
        _ctrl("3.4", "3", "Monitoring", "Ensure CloudMonitor alerts on root account console sign-ins"),
        _ctrl("3.5", "3", "Monitoring", "Ensure Cloud Security Center (Yundun) is enabled"),

        _section("4", "Networking"),
        _ctrl("4.1", "4", "Networking", "Ensure no Security Group allows ingress 0.0.0.0/0 on port 22"),
        _ctrl("4.2", "4", "Networking", "Ensure no Security Group allows ingress 0.0.0.0/0 on port 3389"),
        _ctrl("4.3", "4", "Networking", "Ensure VPC Flow Logs are enabled"),
        _ctrl("4.4", "4", "Networking", "Ensure default Security Groups are restricted"),

        _section("5", "Storage"),
        _ctrl("5.1", "5", "Storage", "Ensure OSS bucket policy denies HTTP requests"),
        _ctrl("5.2", "5", "Storage", "Ensure OSS bucket has no public-read or public-read-write ACL"),
        _ctrl("5.3", "5", "Storage", "Ensure OSS server-side encryption is enabled"),
        _ctrl("5.4", "5", "Storage", "Ensure OSS bucket logging is enabled"),
        _ctrl("5.5", "5", "Storage", "Ensure OSS bucket versioning is enabled"),

        _section("6", "Database"),
        _ctrl("6.1", "6", "Database", "Ensure ApsaraDB RDS encryption is enabled"),
        _ctrl("6.2", "6", "Database", "Ensure ApsaraDB RDS instances are not publicly accessible"),
        _ctrl("6.3", "6", "Database", "Ensure ApsaraDB RDS audit logging is enabled"),
        _ctrl("6.4", "6", "Database", "Ensure ApsaraDB RDS automated backups are configured"),
        _ctrl("6.5", "6", "Database", "Ensure ApsaraDB RDS SSL is required for connections"),

        _section("7", "Compute"),
        _ctrl("7.1", "7", "Compute", "Ensure ECS instance metadata uses hardened mode (token-required)"),
        _ctrl("7.2", "7", "Compute", "Ensure ECS disks are encrypted"),
        _ctrl("7.3", "7", "Compute", "Ensure ECS instances are part of a Security Group"),
        _ctrl("7.4", "7", "Compute", "Ensure ECS public IPs are evaluated periodically"),
    ],
}


# ── CIS Google Cloud Platform Foundation 4.0.0 ────────────────────────────────

CIS_GCP = {
    "framework": "cis_gcp",
    "version": "4.0.0",
    "source": "https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
    "rows": [
        _section("1", "Identity and Access Management"),
        _ctrl("1.1", "1", "Identity and Access Management", "Ensure that Corporate Login Credentials are Used"),
        _ctrl("1.2", "1", "Identity and Access Management", "Ensure that Multi-Factor Authentication is Enabled for All Non-Service Accounts"),
        _ctrl("1.3", "1", "Identity and Access Management", "Ensure that Security Key Enforcement is Enabled for All Admin Accounts"),
        _ctrl("1.4", "1", "Identity and Access Management", "Ensure that there are only GCP-managed service account keys for each service account"),
        _ctrl("1.5", "1", "Identity and Access Management", "Ensure that Service Account has no Admin privileges"),
        _ctrl("1.6", "1", "Identity and Access Management", "Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level"),
        _ctrl("1.7", "1", "Identity and Access Management", "Ensure user-managed/external keys for service accounts are rotated every 90 days or less"),
        _ctrl("1.8", "1", "Identity and Access Management", "Ensure that Separation of Duties is Enforced While Assigning Service Account Related Roles"),
        _ctrl("1.9", "1", "Identity and Access Management", "Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible"),
        _ctrl("1.10", "1", "Identity and Access Management", "Ensure KMS encryption keys are rotated within a period of 90 days"),
        _ctrl("1.11", "1", "Identity and Access Management", "Ensure that Separation of Duties is Enforced While Assigning KMS Related Roles"),
        _ctrl("1.12", "1", "Identity and Access Management", "Ensure API keys are not created for a project"),
        _ctrl("1.13", "1", "Identity and Access Management", "Ensure API keys are restricted to use by only specified Hosts and Apps"),
        _ctrl("1.14", "1", "Identity and Access Management", "Ensure API keys are restricted to only APIs that application needs access"),
        _ctrl("1.15", "1", "Identity and Access Management", "Ensure API keys are rotated every 90 days"),

        _section("2", "Logging and Monitoring"),
        _ctrl("2.1", "2", "Logging and Monitoring", "Ensure that Cloud Audit Logging is configured properly across all services and all users from a project"),
        _ctrl("2.2", "2", "Logging and Monitoring", "Ensure that sinks are configured for all log entries"),
        _ctrl("2.3", "2", "Logging and Monitoring", "Ensure that retention policies on log buckets are configured using Bucket Lock"),
        _ctrl("2.4", "2", "Logging and Monitoring", "Ensure log metric filter and alerts exist for project ownership assignments/changes"),
        _ctrl("2.5", "2", "Logging and Monitoring", "Ensure log metric filter and alerts exist for Audit Configuration changes"),
        _ctrl("2.6", "2", "Logging and Monitoring", "Ensure log metric filter and alerts exist for Custom Role changes"),
        _ctrl("2.7", "2", "Logging and Monitoring", "Ensure log metric filter and alerts exist for VPC Network Firewall rule changes"),
        _ctrl("2.8", "2", "Logging and Monitoring", "Ensure log metric filter and alerts exist for VPC network route changes"),
        _ctrl("2.9", "2", "Logging and Monitoring", "Ensure log metric filter and alerts exist for VPC network changes"),
        _ctrl("2.10", "2", "Logging and Monitoring", "Ensure log metric filter and alerts exist for Cloud Storage IAM permission changes"),
        _ctrl("2.11", "2", "Logging and Monitoring", "Ensure log metric filter and alerts exist for SQL instance configuration changes"),

        _section("3", "Networking"),
        _ctrl("3.1", "3", "Networking", "Ensure the default network does not exist in a project"),
        _ctrl("3.2", "3", "Networking", "Ensure legacy networks do not exist for a project"),
        _ctrl("3.3", "3", "Networking", "Ensure that DNSSEC is enabled for Cloud DNS"),
        _ctrl("3.4", "3", "Networking", "Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC"),
        _ctrl("3.5", "3", "Networking", "Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC"),
        _ctrl("3.6", "3", "Networking", "Ensure that SSH access is restricted from the internet"),
        _ctrl("3.7", "3", "Networking", "Ensure that RDP access is restricted from the internet"),
        _ctrl("3.8", "3", "Networking", "Ensure VPC Flow Logs is enabled for every subnet in a VPC Network"),
        _ctrl("3.9", "3", "Networking", "Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites"),

        _section("4", "Virtual Machines"),
        _ctrl("4.1", "4", "Virtual Machines", "Ensure that instances are not configured to use the default service account"),
        _ctrl("4.2", "4", "Virtual Machines", "Ensure that instances are not configured to use the default service account with full access to all Cloud APIs"),
        _ctrl("4.3", "4", "Virtual Machines", "Ensure 'Block Project-wide SSH keys' is enabled for VM instances"),
        _ctrl("4.4", "4", "Virtual Machines", "Ensure Oslogin is enabled for a Project"),
        _ctrl("4.5", "4", "Virtual Machines", "Ensure 'Enable connecting to serial ports' is not enabled for VM Instance"),
        _ctrl("4.6", "4", "Virtual Machines", "Ensure that IP forwarding is not enabled on Instances"),
        _ctrl("4.7", "4", "Virtual Machines", "Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys"),
        _ctrl("4.8", "4", "Virtual Machines", "Ensure Compute instances are launched with Shielded VM enabled"),
        _ctrl("4.9", "4", "Virtual Machines", "Ensure that Compute instances do not have public IP addresses"),
        _ctrl("4.10", "4", "Virtual Machines", "Ensure App Engine applications enforce HTTPS connections"),
        _ctrl("4.11", "4", "Virtual Machines", "Ensure Confidential Computing is enabled on compute instances"),

        _section("5", "Storage"),
        _ctrl("5.1", "5", "Storage", "Ensure that Cloud Storage bucket is not anonymously or publicly accessible"),
        _ctrl("5.2", "5", "Storage", "Ensure that Cloud Storage buckets have uniform bucket-level access enabled"),

        _section("6", "Cloud SQL Database Services"),
        _ctrl("6.1.1", "6", "Cloud SQL Database Services", "Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges"),
        _ctrl("6.1.2", "6", "Cloud SQL Database Services", "Ensure 'skip_show_database' database flag for Cloud SQL MySQL instance is set to 'on'"),
        _ctrl("6.1.3", "6", "Cloud SQL Database Services", "Ensure 'local_infile' database flag for Cloud SQL MySQL instance is set to 'off'"),
        _ctrl("6.2.1", "6", "Cloud SQL Database Services", "Ensure 'log_checkpoints' database flag for Cloud SQL PostgreSQL is set to 'on'"),
        _ctrl("6.2.2", "6", "Cloud SQL Database Services", "Ensure 'log_connections' database flag for Cloud SQL PostgreSQL is set to 'on'"),
        _ctrl("6.2.3", "6", "Cloud SQL Database Services", "Ensure 'log_disconnections' database flag for Cloud SQL PostgreSQL is set to 'on'"),
        _ctrl("6.2.4", "6", "Cloud SQL Database Services", "Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL is set to 'DEFAULT' or stricter"),
        _ctrl("6.2.5", "6", "Cloud SQL Database Services", "Ensure 'log_min_messages' database flag for Cloud SQL PostgreSQL is set to 'WARNING' or stricter"),
        _ctrl("6.3.1", "6", "Cloud SQL Database Services", "Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server is set to 'off'"),
        _ctrl("6.4", "6", "Cloud SQL Database Services", "Ensure that the 'Cloud SQL database instance' requires all incoming connections to use SSL"),
        _ctrl("6.5", "6", "Cloud SQL Database Services", "Ensure that Cloud SQL database instances are not open to the world"),
        _ctrl("6.6", "6", "Cloud SQL Database Services", "Ensure that Cloud SQL database instances do not have public IPs"),
        _ctrl("6.7", "6", "Cloud SQL Database Services", "Ensure that Cloud SQL database instances are configured with automated backups"),

        _section("7", "BigQuery"),
        _ctrl("7.1", "7", "BigQuery", "Ensure that BigQuery datasets are not anonymously or publicly accessible"),
        _ctrl("7.2", "7", "BigQuery", "Ensure that all BigQuery Tables are encrypted with Customer-managed encryption key (CMEK)"),
        _ctrl("7.3", "7", "BigQuery", "Ensure that a Default Customer-managed encryption key (CMEK) is specified for all BigQuery Data Sets"),
    ],
}


# ── CIS Google Workspace Foundations 1.3.0 ────────────────────────────────────

CIS_GCP_WORKSPACE = {
    "framework": "cis_gcp_workspace",
    "version": "1.3.0",
    "source": "https://www.cisecurity.org/benchmark/google_workspace",
    "rows": [
        _section("1", "Account Security"),
        _ctrl("1.1", "1", "Account Security", "Ensure 2-Step Verification (2SV) is enforced for all users"),
        _ctrl("1.2", "1", "Account Security", "Ensure Login Challenges for Risk-based Logins are enabled"),
        _ctrl("1.3", "1", "Account Security", "Ensure password length is set to at least 12 characters"),
        _ctrl("1.4", "1", "Account Security", "Ensure password reuse prevention is enabled"),
        _ctrl("1.5", "1", "Account Security", "Ensure password expiration policies are enforced"),
        _ctrl("1.6", "1", "Account Security", "Ensure Less Secure App access is disabled"),
        _ctrl("1.7", "1", "Account Security", "Ensure session length is configured for low-trust environments"),
        _ctrl("1.8", "1", "Account Security", "Ensure suspicious login alerts are enabled"),

        _section("2", "Authentication & SSO"),
        _ctrl("2.1", "2", "Authentication & SSO", "Ensure SAML SSO is configured for third-party IdP if used"),
        _ctrl("2.2", "2", "Authentication & SSO", "Ensure context-aware access policies are enforced"),
        _ctrl("2.3", "2", "Authentication & SSO", "Ensure Security Key enforcement for super admins"),

        _section("3", "Gmail Security"),
        _ctrl("3.1", "3", "Gmail Security", "Ensure inbound email scanning (Spam, Phishing, Malware) is enabled"),
        _ctrl("3.2", "3", "Gmail Security", "Ensure DMARC quarantine/reject policy is enforced"),
        _ctrl("3.3", "3", "Gmail Security", "Ensure DKIM signing is enabled for outbound mail"),
        _ctrl("3.4", "3", "Gmail Security", "Ensure SPF records are published"),
        _ctrl("3.5", "3", "Gmail Security", "Ensure compliance footer / disclaimer is configured (if required)"),
        _ctrl("3.6", "3", "Gmail Security", "Ensure encrypted message (S/MIME) is enabled where required"),
        _ctrl("3.7", "3", "Gmail Security", "Ensure attachment compliance scanning is configured"),
        _ctrl("3.8", "3", "Gmail Security", "Ensure pre-delivery message scanning is enabled"),

        _section("4", "Drive & Docs"),
        _ctrl("4.1", "4", "Drive & Docs", "Ensure file sharing outside the organization is restricted by default"),
        _ctrl("4.2", "4", "Drive & Docs", "Ensure shared drive sharing is restricted to organization"),
        _ctrl("4.3", "4", "Drive & Docs", "Ensure Drive content access by Google support is disabled"),
        _ctrl("4.4", "4", "Drive & Docs", "Ensure DLP rules are configured for sensitive content"),
        _ctrl("4.5", "4", "Drive & Docs", "Ensure transferring of ownership when users are removed is configured"),
        _ctrl("4.6", "4", "Drive & Docs", "Ensure offline access policies are restricted"),

        _section("5", "Calendar"),
        _ctrl("5.1", "5", "Calendar", "Ensure external Calendar sharing is restricted to free/busy"),
        _ctrl("5.2", "5", "Calendar", "Ensure calendar interop with non-Google calendars uses HTTPS"),

        _section("6", "Mobile Device Management"),
        _ctrl("6.1", "6", "Mobile Device Management", "Ensure advanced Mobile Management (AMM) is enabled"),
        _ctrl("6.2", "6", "Mobile Device Management", "Ensure device password policy is enforced"),
        _ctrl("6.3", "6", "Mobile Device Management", "Ensure work profile is required on Android"),
        _ctrl("6.4", "6", "Mobile Device Management", "Ensure rooted/jailbroken devices are blocked"),

        _section("7", "Logging & Auditing"),
        _ctrl("7.1", "7", "Logging & Auditing", "Ensure audit logs are exported to BigQuery / SIEM"),
        _ctrl("7.2", "7", "Logging & Auditing", "Ensure alert center alerts are reviewed regularly"),
        _ctrl("7.3", "7", "Logging & Auditing", "Ensure data residency policies are configured if needed"),
    ],
}


# ── CIS Microsoft 365 Foundations 6.0.1 ───────────────────────────────────────

CIS_M365 = {
    "framework": "cis_m365",
    "version": "6.0.1",
    "source": "https://www.cisecurity.org/benchmark/microsoft_365",
    "rows": [
        _section("1", "Account / Authentication Policies"),
        _ctrl("1.1.1", "1", "Account / Authentication Policies", "Ensure Security Defaults is enabled or Conditional Access policies are configured"),
        _ctrl("1.1.2", "1", "Account / Authentication Policies", "Ensure that an exclusionary Geographic Access Policy is considered"),
        _ctrl("1.1.3", "1", "Account / Authentication Policies", "Ensure A Multi-factor Authentication Policy Exists for All Users"),
        _ctrl("1.1.4", "1", "Account / Authentication Policies", "Ensure Multi-factor Authentication is Required for Risky Sign-ins"),
        _ctrl("1.1.5", "1", "Account / Authentication Policies", "Ensure modern authentication for SharePoint applications is required"),
        _ctrl("1.1.6", "1", "Account / Authentication Policies", "Ensure Sign-in frequency is enabled and browser sessions are not persistent"),
        _ctrl("1.1.7", "1", "Account / Authentication Policies", "Ensure 'LinkedIn account connections' is disabled"),
        _ctrl("1.2.1", "1", "Account / Authentication Policies", "Ensure modern authentication for Exchange Online is enabled"),
        _ctrl("1.2.2", "1", "Account / Authentication Policies", "Ensure modern authentication for Skype for Business Online is enabled"),
        _ctrl("1.3.1", "1", "Account / Authentication Policies", "Ensure 'User consent for applications' is set to 'Do not allow user consent'"),
        _ctrl("1.3.2", "1", "Account / Authentication Policies", "Ensure 'User consent for applications' is set to 'Allow for Verified Publishers'"),
        _ctrl("1.4.1", "1", "Account / Authentication Policies", "Ensure 'Self-service password reset enabled' is set to 'All'"),
        _ctrl("1.4.2", "1", "Account / Authentication Policies", "Ensure 'Number of methods required to reset' is set to '2'"),
        _ctrl("1.5", "1", "Account / Authentication Policies", "Ensure that account 'Lockout Threshold' is less than or equal to 10"),

        _section("2", "Application Permissions"),
        _ctrl("2.1.1", "2", "Application Permissions", "Ensure Microsoft Defender for Office 365 Safe Links policies are configured"),
        _ctrl("2.1.2", "2", "Application Permissions", "Ensure Microsoft Defender for Office 365 Safe Attachments policies are configured"),
        _ctrl("2.1.3", "2", "Application Permissions", "Ensure Anti-Phishing Policy is configured"),
        _ctrl("2.1.4", "2", "Application Permissions", "Ensure DKIM is enabled for all Exchange Online Domains"),
        _ctrl("2.1.5", "2", "Application Permissions", "Ensure SPF records are published for all Exchange Domains"),
        _ctrl("2.1.6", "2", "Application Permissions", "Ensure DMARC Records for all Exchange Online domains are published"),
        _ctrl("2.1.7", "2", "Application Permissions", "Ensure that an anti-malware policy is enabled"),
        _ctrl("2.1.8", "2", "Application Permissions", "Ensure Common Attachment Types Filter is enabled"),
        _ctrl("2.1.9", "2", "Application Permissions", "Ensure Outbound Spam policy notifications are enabled"),
        _ctrl("2.1.10", "2", "Application Permissions", "Ensure auditing of Connection Filter Policy is enabled"),

        _section("3", "Data Management"),
        _ctrl("3.1.1", "3", "Data Management", "Ensure Microsoft 365 audit log search is Enabled"),
        _ctrl("3.1.2", "3", "Data Management", "Ensure mailbox auditing is Enabled for all user mailboxes"),
        _ctrl("3.2.1", "3", "Data Management", "Ensure DLP policies are enabled for Exchange Online"),
        _ctrl("3.2.2", "3", "Data Management", "Ensure DLP policies are enabled for SharePoint Online and OneDrive"),
        _ctrl("3.3", "3", "Data Management", "Ensure SharePoint Online Information Protection policies are set up and used"),

        _section("4", "Email Security / Exchange Online"),
        _ctrl("4.1", "4", "Email Security / Exchange Online", "Ensure 'External In Outlook' setting is Enabled"),
        _ctrl("4.2", "4", "Email Security / Exchange Online", "Ensure Mail Forwarding rules to external domains are restricted"),
        _ctrl("4.3", "4", "Email Security / Exchange Online", "Ensure mail transport rules do not whitelist specific domains"),
        _ctrl("4.4", "4", "Email Security / Exchange Online", "Ensure mail transport rules do not forward email to external domains"),
        _ctrl("4.5", "4", "Email Security / Exchange Online", "Ensure the 'Spoofed senders' policy is enabled"),
        _ctrl("4.6", "4", "Email Security / Exchange Online", "Ensure no mailboxes have Auto-Forward enabled"),

        _section("5", "Auditing / Logging"),
        _ctrl("5.1.1", "5", "Auditing / Logging", "Ensure Azure AD Sign-In log alerts are configured"),
        _ctrl("5.1.2", "5", "Auditing / Logging", "Ensure 'Privileged role assignment' alert is configured"),
        _ctrl("5.1.3", "5", "Auditing / Logging", "Ensure 'Risky sign-in' alerts are configured"),
        _ctrl("5.1.4", "5", "Auditing / Logging", "Ensure 'User risk' alerts are configured"),
        _ctrl("5.1.5", "5", "Auditing / Logging", "Ensure unified audit log retention policy is configured"),
        _ctrl("5.1.6", "5", "Auditing / Logging", "Ensure that auditing is enabled for Microsoft 365 services"),

        _section("6", "Storage / SharePoint Online"),
        _ctrl("6.1", "6", "Storage / SharePoint Online", "Ensure external file sharing is restricted in SharePoint Online"),
        _ctrl("6.2", "6", "Storage / SharePoint Online", "Ensure Anonymous links expire within X days"),
        _ctrl("6.3", "6", "Storage / SharePoint Online", "Ensure 'Allow members to share' setting matches policy"),
        _ctrl("6.4", "6", "Storage / SharePoint Online", "Ensure default link permission is 'View'"),
        _ctrl("6.5", "6", "Storage / SharePoint Online", "Ensure OneDrive sync is restricted to Domain-joined devices"),
        _ctrl("6.6", "6", "Storage / SharePoint Online", "Ensure files are blocked from being downloaded to non-managed devices"),

        _section("7", "Microsoft Teams"),
        _ctrl("7.1", "7", "Microsoft Teams", "Ensure external access is restricted to allowed domains"),
        _ctrl("7.2", "7", "Microsoft Teams", "Ensure guest access is configured per policy"),
        _ctrl("7.3", "7", "Microsoft Teams", "Ensure communication settings are configured per policy"),
        _ctrl("7.4", "7", "Microsoft Teams", "Ensure file storage settings are configured per policy"),
        _ctrl("7.5", "7", "Microsoft Teams", "Ensure third-party app installation is restricted"),
    ],
}


# ── CIS Azure Kubernetes Service (AKS) 2.0.0 ──────────────────────────────────

CIS_AKS = {
    "framework": "cis_aks",
    "version": "2.0.0",
    "source": "https://www.cisecurity.org/benchmark/kubernetes",
    "rows": [
        _section("2", "Cluster Configuration"),
        _ctrl("2.1.1", "2", "Cluster Configuration", "Ensure that the Default Namespace is not used"),

        _section("3", "Worker Nodes"),
        _ctrl("3.1.1", "3", "Worker Nodes", "Ensure that the kubeconfig file permissions are 644 or more restrictive"),
        _ctrl("3.1.2", "3", "Worker Nodes", "Ensure that the kubelet service file permissions are 644 or more restrictive"),
        _ctrl("3.1.3", "3", "Worker Nodes", "Ensure that the kubelet service file ownership is set to root:root"),
        _ctrl("3.1.4", "3", "Worker Nodes", "Ensure that the proxy kubeconfig file permissions are 644 or more restrictive"),
        _ctrl("3.2.1", "3", "Worker Nodes", "Ensure that the --anonymous-auth argument is set to false"),
        _ctrl("3.2.2", "3", "Worker Nodes", "Ensure that the --authorization-mode argument is not set to AlwaysAllow"),
        _ctrl("3.2.3", "3", "Worker Nodes", "Ensure that the --client-ca-file argument is set"),
        _ctrl("3.2.4", "3", "Worker Nodes", "Ensure that the --read-only-port argument is set to 0"),
        _ctrl("3.2.5", "3", "Worker Nodes", "Ensure that the --streaming-connection-idle-timeout argument is not set to 0"),
        _ctrl("3.2.6", "3", "Worker Nodes", "Ensure that the --protect-kernel-defaults argument is set to true"),
        _ctrl("3.2.7", "3", "Worker Nodes", "Ensure that the --make-iptables-util-chains argument is set to true"),
        _ctrl("3.2.8", "3", "Worker Nodes", "Ensure that the --hostname-override argument is not set"),
        _ctrl("3.2.9", "3", "Worker Nodes", "Ensure that the --event-qps argument is set to a level which ensures appropriate event capture"),
        _ctrl("3.2.10", "3", "Worker Nodes", "Ensure that the --rotate-certificates argument is not set to false"),

        _section("4", "Policies"),
        _ctrl("4.1.1", "4", "Policies", "Ensure that the cluster-admin role is only used where required"),
        _ctrl("4.1.2", "4", "Policies", "Minimize access to secrets"),
        _ctrl("4.1.3", "4", "Policies", "Minimize wildcard use in Roles and ClusterRoles"),
        _ctrl("4.1.4", "4", "Policies", "Minimize access to create pods"),
        _ctrl("4.1.5", "4", "Policies", "Ensure that default service accounts are not actively used"),
        _ctrl("4.1.6", "4", "Policies", "Ensure that Service Account Tokens are only mounted where necessary"),
        _ctrl("4.2.1", "4", "Policies", "Minimize the admission of privileged containers"),
        _ctrl("4.2.2", "4", "Policies", "Minimize the admission of containers wishing to share the host process ID namespace"),
        _ctrl("4.2.3", "4", "Policies", "Minimize the admission of containers wishing to share the host IPC namespace"),
        _ctrl("4.2.4", "4", "Policies", "Minimize the admission of containers wishing to share the host network namespace"),
        _ctrl("4.2.5", "4", "Policies", "Minimize the admission of containers with allowPrivilegeEscalation"),
        _ctrl("4.2.6", "4", "Policies", "Minimize the admission of root containers"),
        _ctrl("4.2.7", "4", "Policies", "Minimize the admission of containers with the NET_RAW capability"),
        _ctrl("4.2.8", "4", "Policies", "Minimize the admission of containers with added capabilities"),
        _ctrl("4.3.1", "4", "Policies", "Ensure CNI plugin supports network policies"),
        _ctrl("4.3.2", "4", "Policies", "Ensure that all Namespaces have Network Policies defined"),
        _ctrl("4.4.1", "4", "Policies", "Prefer using secrets as files over secrets as environment variables"),
        _ctrl("4.4.2", "4", "Policies", "Consider external secret storage"),
        _ctrl("4.5.1", "4", "Policies", "Configure Image Provenance using ImagePolicyWebhook admission controller"),
        _ctrl("4.6.1", "4", "Policies", "Create administrative boundaries between resources using namespaces"),
        _ctrl("4.6.2", "4", "Policies", "Apply Security Context to Your Pods and Containers"),
        _ctrl("4.6.3", "4", "Policies", "The default namespace should not be used"),

        _section("5", "Managed Services"),
        _ctrl("5.1.1", "5", "Managed Services", "Ensure Image Vulnerability Scanning using ACR or third party provider"),
        _ctrl("5.1.2", "5", "Managed Services", "Minimize user access to Container Image repositories"),
        _ctrl("5.1.3", "5", "Managed Services", "Minimize cluster access to read-only for Container Image repositories"),
        _ctrl("5.1.4", "5", "Managed Services", "Minimize Container Registries to only those approved"),
        _ctrl("5.2.1", "5", "Managed Services", "Prefer using dedicated AKS Service Accounts"),
        _ctrl("5.3.1", "5", "Managed Services", "Ensure Kubernetes Secrets are encrypted using customer managed keys"),
        _ctrl("5.4.1", "5", "Managed Services", "Restrict Access to the Control Plane Endpoint"),
        _ctrl("5.4.2", "5", "Managed Services", "Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled"),
        _ctrl("5.4.3", "5", "Managed Services", "Ensure clusters are created with Private Nodes"),
        _ctrl("5.4.4", "5", "Managed Services", "Ensure Network Policy is Enabled and set as appropriate"),
        _ctrl("5.4.5", "5", "Managed Services", "Encrypt traffic to HTTPS load balancers with TLS certificates"),
        _ctrl("5.5.1", "5", "Managed Services", "Manage Kubernetes RBAC users with Microsoft Entra ID"),
        _ctrl("5.5.2", "5", "Managed Services", "Use Azure RBAC for Kubernetes Authorization"),
    ],
}


# ── CIS Microsoft Azure Compute Services 2.0.0 ────────────────────────────────

CIS_AZURE_COMPUTE = {
    "framework": "cis_azure_compute",
    "version": "2.0.0",
    "source": "https://www.cisecurity.org/benchmark/azure",
    "rows": [
        _section("1", "Virtual Machines"),
        _ctrl("1.1", "1", "Virtual Machines", "Ensure VM disk encryption is enabled (OS disk)"),
        _ctrl("1.2", "1", "Virtual Machines", "Ensure VM disk encryption is enabled (data disks)"),
        _ctrl("1.3", "1", "Virtual Machines", "Ensure unattached managed disks are encrypted with CMK"),
        _ctrl("1.4", "1", "Virtual Machines", "Ensure 'Endpoint protection' is installed on VMs"),
        _ctrl("1.5", "1", "Virtual Machines", "Ensure Trusted Launch is enabled on supported VMs"),
        _ctrl("1.6", "1", "Virtual Machines", "Ensure 'Secure boot' is enabled on supported VMs"),
        _ctrl("1.7", "1", "Virtual Machines", "Ensure 'vTPM' is enabled on supported VMs"),
        _ctrl("1.8", "1", "Virtual Machines", "Ensure VMs use Managed Identities (System or User assigned)"),
        _ctrl("1.9", "1", "Virtual Machines", "Ensure only approved VM extensions are installed"),
        _ctrl("1.10", "1", "Virtual Machines", "Ensure VMs are part of a Backup vault with retention >= 30 days"),
        _ctrl("1.11", "1", "Virtual Machines", "Ensure VM update management is configured"),

        _section("2", "Virtual Machine Scale Sets"),
        _ctrl("2.1", "2", "Virtual Machine Scale Sets", "Ensure VMSS automatic OS upgrades are enabled"),
        _ctrl("2.2", "2", "Virtual Machine Scale Sets", "Ensure VMSS use ephemeral or encrypted OS disks"),
        _ctrl("2.3", "2", "Virtual Machine Scale Sets", "Ensure VMSS instance view diagnostics are enabled"),

        _section("3", "App Service / Functions"),
        _ctrl("3.1", "3", "App Service / Functions", "Ensure App Service uses HTTPS-only"),
        _ctrl("3.2", "3", "App Service / Functions", "Ensure App Service minimum TLS version is 1.2"),
        _ctrl("3.3", "3", "App Service / Functions", "Ensure App Service uses Managed Identity (no inline secrets)"),
        _ctrl("3.4", "3", "App Service / Functions", "Ensure App Service authentication is enabled"),
        _ctrl("3.5", "3", "App Service / Functions", "Ensure App Service FTP/FTPS is disabled or set to FTPS-only"),
        _ctrl("3.6", "3", "App Service / Functions", "Ensure remote debugging is disabled in production"),
        _ctrl("3.7", "3", "App Service / Functions", "Ensure App Service Stack runtime version is current"),
        _ctrl("3.8", "3", "App Service / Functions", "Ensure App Service uses Private Endpoints / VNet integration"),

        _section("4", "Container Instances / Container Apps"),
        _ctrl("4.1", "4", "Container Instances / Container Apps", "Ensure ACI uses Managed Identity for image pull"),
        _ctrl("4.2", "4", "Container Instances / Container Apps", "Ensure ACI/Container Apps run with read-only root filesystem where possible"),
        _ctrl("4.3", "4", "Container Instances / Container Apps", "Ensure ACI/Container Apps drop all unnecessary capabilities"),
        _ctrl("4.4", "4", "Container Instances / Container Apps", "Ensure container images are pulled from approved ACR registries"),

        _section("5", "Service Fabric"),
        _ctrl("5.1", "5", "Service Fabric", "Ensure Service Fabric cluster uses certificate-based authentication"),
        _ctrl("5.2", "5", "Service Fabric", "Ensure Service Fabric clientCertificateThumbprints are configured"),
        _ctrl("5.3", "5", "Service Fabric", "Ensure Service Fabric reverse proxy enforces HTTPS"),

        _section("6", "Batch"),
        _ctrl("6.1", "6", "Batch", "Ensure Batch pools use VNet-integrated subnets"),
        _ctrl("6.2", "6", "Batch", "Ensure Batch account uses customer-managed keys for encryption"),
        _ctrl("6.3", "6", "Batch", "Ensure Batch account public network access is disabled"),
    ],
}


# ── OS / network / app benchmarks: SECTION SCAFFOLDING ONLY ───────────────────

CIS_WINDOWS_SERVER = {
    "framework": "cis_windows_server",
    "version": "2.0.0",
    "source": "https://www.cisecurity.org/benchmark/microsoft_windows_server",
    "rows": [
        _section("1", "Account Policies"),
        _section("2", "Local Policies"),
        _section("5", "System Services"),
        _section("9", "Windows Defender Firewall with Advanced Security"),
        _section("17", "Advanced Audit Policy Configuration"),
        _section("18", "Administrative Templates (Computer)"),
        _section("19", "Administrative Templates (User)"),
        _section("L1", "Level 1 — Member Server"),
        _section("L2", "Level 2 — Member Server"),
        _section("L1-DC", "Level 1 — Domain Controller"),
        _section("L2-DC", "Level 2 — Domain Controller"),
    ],
}

CIS_UBUNTU = {
    "framework": "cis_ubuntu",
    "version": "3.0.0",
    "source": "https://www.cisecurity.org/benchmark/ubuntu_linux",
    "rows": [
        _section("1", "Initial Setup"),
        _section("2", "Services"),
        _section("3", "Network Configuration"),
        _section("4", "Logging and Auditing"),
        _section("5", "Access, Authentication and Authorization"),
        _section("6", "System Maintenance"),
    ],
}

CIS_ESXI = {
    "framework": "cis_esxi",
    "version": "1.3.0",
    "source": "https://www.cisecurity.org/benchmark/vmware",
    "rows": [
        _section("1", "Install"),
        _section("2", "Communication"),
        _section("3", "Logging"),
        _section("4", "Access"),
        _section("5", "Console"),
        _section("6", "Storage"),
        _section("7", "Network"),
        _section("8", "Virtual Machines"),
    ],
}

CIS_F5 = {
    "framework": "cis_f5",
    "version": "1.0.0",
    "source": "https://www.cisecurity.org/benchmark/f5_networks",
    "rows": [
        _section("1", "User Accounts and Authentication"),
        _section("2", "Logging and Auditing"),
        _section("3", "Network Configuration"),
        _section("4", "TLS / SSL Settings"),
        _section("5", "iRules and Modules"),
    ],
}

CIS_PALO_ALTO = {
    "framework": "cis_palo_alto",
    "version": "1.2.0",
    "source": "https://www.cisecurity.org/benchmark/palo_alto",
    "rows": [
        _section("1", "Device Setup"),
        _section("2", "Authentication, Authorization & Logging"),
        _section("3", "High Availability"),
        _section("4", "Network Settings"),
        _section("5", "Security Policies"),
        _section("6", "Threat Prevention Profiles"),
        _section("7", "Decryption"),
    ],
}

CIS_MSSQL = {
    "framework": "cis_mssql",
    "version": "1.0.0",
    "source": "https://www.cisecurity.org/benchmark/microsoft_sql_server",
    "rows": [
        _section("1", "Installation, Updates and Patches"),
        _section("2", "Surface Area Reduction"),
        _section("3", "Authentication and Authorization"),
        _section("4", "Password Policies"),
        _section("5", "Auditing and Logging"),
        _section("6", "Application Development"),
        _section("7", "Encryption"),
        _section("8", "Appendix"),
    ],
}


ALL_BENCHMARKS = [
    CIS_AZURE, CIS_AWS, CIS_AWS_DB, CIS_ALIBABA,
    CIS_GCP, CIS_GCP_WORKSPACE, CIS_M365, CIS_AKS, CIS_AZURE_COMPUTE,
    CIS_WINDOWS_SERVER, CIS_UBUNTU, CIS_ESXI,
    CIS_F5, CIS_PALO_ALTO, CIS_MSSQL,
]


def to_json_payload(benchmark: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a benchmark dict into the standard catalog JSON payload."""
    controls: List[Dict[str, Any]] = []
    for control_id, parent, domain, title, weight in benchmark["rows"]:
        controls.append({
            "control_id": control_id,
            "parent": parent,
            "domain": domain,
            "title": title,
            "description": title,
            "weight": weight,
        })
    return {
        "framework": benchmark["framework"],
        "version": benchmark["version"],
        "source": benchmark["source"],
        "controls": controls,
    }
