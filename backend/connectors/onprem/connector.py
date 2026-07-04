"""
NexGenCyberAI - On-Premises Connector
Connects via Nessus REST API or OpenVAS GMP for VA scanning.
Also supports SSH-based configuration checks on Linux/Windows hosts.
Supports AD/LDAP checks, WinRM-based Windows hardening checks, and
SSH/paramiko-based Linux checks via run_configuration_review().
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List
import httpx
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

logger = logging.getLogger(__name__)

NESSUS_SEVERITY = {0: FindingSeverity.INFO, 1: FindingSeverity.LOW, 2: FindingSeverity.MEDIUM,
                   3: FindingSeverity.HIGH, 4: FindingSeverity.CRITICAL}

# userAccountControl flag: account is disabled
UF_ACCOUNTDISABLE = 0x0002


class OnPremConnector(BaseConnector):

    @property
    def _nessus_url(self):
        return self.credentials.get("nessus_url", "https://localhost:8834")

    async def _nessus_get(self, path: str) -> Dict:
        token = self.credentials.get("nessus_api_key", "")
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            resp = await client.get(
                f"{self._nessus_url}{path}",
                headers={"X-ApiKeys": f"accessKey={token}; secretKey={self.credentials.get('nessus_secret_key', '')}"},
            )
        resp.raise_for_status()
        return resp.json()

    async def test_connection(self) -> ConnectorTestResult:
        try:
            data = await self._nessus_get("/server/status")
            return ConnectorTestResult(success=True, message=f"Nessus status: {data.get('status')}", details=data)
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    async def get_resources(self) -> List[Dict[str, Any]]:
        try:
            data = await self._nessus_get("/scans")
            return data.get("scans", [])
        except Exception:
            return []

    # ── LDAP helpers ────────────────────────────────────────────────────────────

    def _get_ldap_conn(self):
        """Return an ldap3 Connection bound to the AD server, or None."""
        try:
            import ldap3
        except ImportError:
            logger.warning("ldap3 not installed; skipping AD checks")
            return None, None
        ad_server = self.credentials.get("ad_server")
        ad_user = self.credentials.get("ad_user")
        ad_password = self.credentials.get("ad_password")
        if not (ad_server and ad_user and ad_password):
            return None, None
        try:
            server = ldap3.Server(ad_server, get_info=ldap3.ALL, connect_timeout=10)
            conn = ldap3.Connection(server, user=ad_user, password=ad_password, auto_bind=True)
            return conn, server
        except Exception as exc:
            logger.warning("LDAP connection failed: %s", exc)
            return None, None

    def _get_ad_base_dn(self) -> str:
        return self.credentials.get("ad_base_dn", "DC=corp,DC=local")

    # ── Active Directory checks ─────────────────────────────────────────────────

    def _check_ad_stale_accounts(self) -> List[ConnectorFinding]:
        """LDAP query for enabled users whose pwdLastSet or lastLogonTimestamp
        is older than 90 days. HIGH for 180+ days, MEDIUM for 90+ days."""
        findings = []
        try:
            conn, _ = self._get_ldap_conn()
            if conn is None:
                return findings
            import ldap3
            now = datetime.now(timezone.utc)
            threshold_90 = now - timedelta(days=90)
            threshold_180 = now - timedelta(days=180)
            # Windows FILETIME epoch: 100-ns intervals since 1601-01-01
            _EPOCH_DELTA = 116444736000000000

            def _filetime_to_dt(ft: int) -> datetime:
                return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=(ft - _EPOCH_DELTA) // 10)

            base_dn = self._get_ad_base_dn()
            conn.search(
                base_dn,
                "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName", "pwdLastSet", "lastLogonTimestamp", "userAccountControl"],
            )
            for entry in conn.entries:
                sam = str(entry.sAMAccountName)
                pwd_last_set = 0
                last_logon = 0
                try:
                    pwd_last_set = int(entry.pwdLastSet.value) if entry.pwdLastSet.value else 0
                except Exception:
                    pass
                try:
                    last_logon = int(entry.lastLogonTimestamp.value) if entry.lastLogonTimestamp.value else 0
                except Exception:
                    pass
                # Determine most recent activity date
                dt_pwd = _filetime_to_dt(pwd_last_set) if pwd_last_set > 0 else None
                dt_logon = _filetime_to_dt(last_logon) if last_logon > 0 else None
                last_active = max(filter(None, [dt_pwd, dt_logon]), default=None)
                if last_active is None:
                    # Never logged in / no password set — treat as 180+ days
                    severity = FindingSeverity.HIGH
                    days_inactive = "unknown"
                elif last_active < threshold_180:
                    severity = FindingSeverity.HIGH
                    days_inactive = (now - last_active).days
                elif last_active < threshold_90:
                    severity = FindingSeverity.MEDIUM
                    days_inactive = (now - last_active).days
                else:
                    continue
                findings.append(ConnectorFinding(
                    title=f"Stale AD account: {sam}",
                    description=(
                        f"Enabled AD user '{sam}' has been inactive for {days_inactive} days "
                        f"(last activity: {last_active.date() if last_active else 'never'}). "
                        "Stale accounts increase the risk of credential compromise."
                    ),
                    severity=severity,
                    resource_id=sam,
                    resource_type="AD User Account",
                    control_id="NIST AC-2",
                    framework="nist_800_53",
                    remediation="Disable or remove inactive AD accounts per the account management policy.",
                ))
        except Exception as exc:
            logger.warning("_check_ad_stale_accounts failed: %s", exc)
        return findings

    def _check_ad_privileged_groups(self) -> List[ConnectorFinding]:
        """LDAP query for members of privileged AD groups. Flag Domain Admins
        with > 5 members (HIGH) and any *admin* group with > 10 members (MEDIUM)."""
        findings = []
        try:
            conn, _ = self._get_ldap_conn()
            if conn is None:
                return findings
            base_dn = self._get_ad_base_dn()
            target_groups = [
                "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"
            ]
            for group_name in target_groups:
                try:
                    conn.search(
                        base_dn,
                        f"(&(objectClass=group)(cn={group_name}))",
                        attributes=["member", "cn"],
                    )
                    if not conn.entries:
                        continue
                    entry = conn.entries[0]
                    members = entry.member.values if entry.member else []
                    member_count = len(members)
                    if group_name == "Domain Admins" and member_count > 5:
                        findings.append(ConnectorFinding(
                            title=f"Excessive Domain Admins members ({member_count})",
                            description=(
                                f"The 'Domain Admins' group has {member_count} members, exceeding the "
                                "recommended maximum of 5. Excessive Domain Admin accounts significantly "
                                "expand the attack surface."
                            ),
                            severity=FindingSeverity.HIGH,
                            resource_id=group_name,
                            resource_type="AD Group",
                            control_id="NIST AC-6",
                            framework="nist_800_53",
                            remediation=(
                                "Reduce Domain Admins membership to the minimum required. "
                                "Use tiered administration and just-in-time privileged access."
                            ),
                            evidence={"group": group_name, "member_count": member_count},
                        ))
                except Exception as exc:
                    logger.warning("Failed to query group %s: %s", group_name, exc)
            # Scan for any group with "admin" in the name and > 10 members
            try:
                conn.search(
                    base_dn,
                    "(&(objectClass=group)(cn=*admin*))",
                    attributes=["member", "cn"],
                )
                for entry in conn.entries:
                    cn = str(entry.cn)
                    if cn in target_groups:
                        continue  # already handled above
                    members = entry.member.values if entry.member else []
                    if len(members) > 10:
                        findings.append(ConnectorFinding(
                            title=f"Large admin group: {cn} ({len(members)} members)",
                            description=(
                                f"AD group '{cn}' contains 'admin' in its name and has {len(members)} members, "
                                "exceeding the recommended maximum of 10."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            resource_id=cn,
                            resource_type="AD Group",
                            control_id="NIST AC-6",
                            framework="nist_800_53",
                            remediation="Review membership of administrative groups and apply least-privilege.",
                            evidence={"group": cn, "member_count": len(members)},
                        ))
            except Exception as exc:
                logger.warning("Failed to query admin groups: %s", exc)
        except Exception as exc:
            logger.warning("_check_ad_privileged_groups failed: %s", exc)
        return findings

    def _check_ad_password_policy(self) -> List[ConnectorFinding]:
        """LDAP query for Default Domain Policy password settings.
        Flags weak minPwdLength, excessive maxPwdAge, and zero lockoutThreshold."""
        findings = []
        try:
            conn, _ = self._get_ldap_conn()
            if conn is None:
                return findings
            base_dn = self._get_ad_base_dn()
            conn.search(
                base_dn,
                "(objectClass=domainDNS)",
                attributes=["minPwdLength", "maxPwdAge", "lockoutThreshold", "pwdHistoryLength"],
                search_scope="BASE",
            )
            if not conn.entries:
                logger.warning("Could not retrieve domain password policy")
                return findings
            entry = conn.entries[0]
            # minPwdLength
            try:
                min_len = int(entry.minPwdLength.value or 0)
                if min_len < 12:
                    findings.append(ConnectorFinding(
                        title=f"Weak minimum password length ({min_len} characters)",
                        description=(
                            f"The Default Domain Policy minimum password length is {min_len}, "
                            "below the recommended 12 characters."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        resource_id="Default Domain Policy",
                        resource_type="AD Password Policy",
                        control_id="NIST IA-5",
                        framework="nist_800_53",
                        remediation="Set the minimum password length to at least 12 characters.",
                        evidence={"minPwdLength": min_len},
                    ))
            except Exception as exc:
                logger.warning("Failed to parse minPwdLength: %s", exc)
            # maxPwdAge (negative 100-ns intervals; 0 = never expires)
            try:
                max_age_raw = int(entry.maxPwdAge.value or 0)
                if max_age_raw == 0:
                    max_age_days = 0
                else:
                    max_age_days = abs(max_age_raw) // (10_000_000 * 86400)
                if max_age_days == 0 or max_age_days > 365:
                    age_str = "never expires" if max_age_days == 0 else f"{max_age_days} days"
                    findings.append(ConnectorFinding(
                        title=f"Excessive or unlimited password age ({age_str})",
                        description=(
                            f"The Default Domain Policy maximum password age is {age_str}. "
                            "Passwords that never expire or have extremely long lifetimes increase breach risk."
                        ),
                        severity=FindingSeverity.HIGH,
                        resource_id="Default Domain Policy",
                        resource_type="AD Password Policy",
                        control_id="NIST IA-5",
                        framework="nist_800_53",
                        remediation="Set the maximum password age to 90 or fewer days.",
                        evidence={"maxPwdAge_days": max_age_days},
                    ))
            except Exception as exc:
                logger.warning("Failed to parse maxPwdAge: %s", exc)
            # lockoutThreshold
            try:
                lockout = int(entry.lockoutThreshold.value or 0)
                if lockout == 0:
                    findings.append(ConnectorFinding(
                        title="Account lockout threshold not configured (0 — unlimited attempts)",
                        description=(
                            "The Default Domain Policy lockout threshold is 0, meaning accounts are never "
                            "locked out after failed logon attempts. This permits brute-force attacks."
                        ),
                        severity=FindingSeverity.HIGH,
                        resource_id="Default Domain Policy",
                        resource_type="AD Password Policy",
                        control_id="NIST IA-5",
                        framework="nist_800_53",
                        remediation="Set the account lockout threshold to 5 or fewer failed attempts.",
                        evidence={"lockoutThreshold": lockout},
                    ))
            except Exception as exc:
                logger.warning("Failed to parse lockoutThreshold: %s", exc)
        except Exception as exc:
            logger.warning("_check_ad_password_policy failed: %s", exc)
        return findings

    def _check_ad_guest_account(self) -> List[ConnectorFinding]:
        """Check if the built-in Guest account is enabled."""
        findings = []
        try:
            conn, _ = self._get_ldap_conn()
            if conn is None:
                return findings
            base_dn = self._get_ad_base_dn()
            conn.search(
                base_dn,
                "(&(objectClass=user)(sAMAccountName=Guest))",
                attributes=["userAccountControl", "sAMAccountName"],
            )
            for entry in conn.entries:
                uac = int(entry.userAccountControl.value or 0)
                if not (uac & UF_ACCOUNTDISABLE):
                    findings.append(ConnectorFinding(
                        title="Built-in Guest account is enabled",
                        description=(
                            "The built-in Guest account is enabled in Active Directory. "
                            "An enabled Guest account allows unauthenticated or anonymous access "
                            "and is a well-known attack vector."
                        ),
                        severity=FindingSeverity.HIGH,
                        resource_id="Guest",
                        resource_type="AD User Account",
                        control_id="NIST AC-2",
                        framework="nist_800_53",
                        remediation="Disable the built-in Guest account via Group Policy or AD Users and Computers.",
                    ))
        except Exception as exc:
            logger.warning("_check_ad_guest_account failed: %s", exc)
        return findings

    def _check_ad_krbtgt_age(self) -> List[ConnectorFinding]:
        """Check how long ago the krbtgt account password was last set.
        If older than 180 days → HIGH (Golden Ticket risk)."""
        findings = []
        try:
            conn, _ = self._get_ldap_conn()
            if conn is None:
                return findings
            base_dn = self._get_ad_base_dn()
            conn.search(
                base_dn,
                "(&(objectClass=user)(sAMAccountName=krbtgt))",
                attributes=["pwdLastSet", "sAMAccountName"],
            )
            if not conn.entries:
                return findings
            entry = conn.entries[0]
            _EPOCH_DELTA = 116444736000000000
            pwd_last_set = int(entry.pwdLastSet.value or 0)
            if pwd_last_set == 0:
                days_old = 999
                last_set_str = "never rotated"
            else:
                dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
                    microseconds=(pwd_last_set - _EPOCH_DELTA) // 10
                )
                days_old = (datetime.now(timezone.utc) - dt).days
                last_set_str = dt.date().isoformat()
            if days_old >= 180:
                findings.append(ConnectorFinding(
                    title=f"krbtgt password has not been rotated in {days_old} days — Golden Ticket risk",
                    description=(
                        f"The krbtgt account password was last set {last_set_str} ({days_old} days ago). "
                        "An old krbtgt password allows attackers who have ever obtained the hash to forge "
                        "Kerberos Golden Tickets indefinitely."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_id="krbtgt",
                    resource_type="AD Service Account",
                    control_id="NIST IA-5",
                    framework="nist_800_53",
                    remediation=(
                        "Rotate the krbtgt password twice (to invalidate existing tickets) using the "
                        "Microsoft KRBTGT Account Password Reset Script. Schedule rotation every 180 days."
                    ),
                    evidence={"pwdLastSet": last_set_str, "days_old": days_old},
                ))
        except Exception as exc:
            logger.warning("_check_ad_krbtgt_age failed: %s", exc)
        return findings

    # ── Windows hardening checks (WinRM) ────────────────────────────────────────

    def _get_winrm_session(self):
        """Return a winrm.Session for the target Windows host, or None."""
        try:
            import winrm
        except ImportError:
            logger.warning("pywinrm not installed; skipping WinRM-based Windows checks")
            return None
        host = self.credentials.get("winrm_host")
        username = self.credentials.get("winrm_user")
        password = self.credentials.get("winrm_password")
        if not (host and username and password):
            return None
        try:
            transport = self.credentials.get("winrm_transport", "ntlm")
            port = int(self.credentials.get("winrm_port", 5985))
            session = winrm.Session(
                f"http://{host}:{port}/wsman",
                auth=(username, password),
                transport=transport,
            )
            return session
        except Exception as exc:
            logger.warning("WinRM session creation failed: %s", exc)
            return None

    def _winrm_ps(self, session, script: str) -> str:
        """Run a PowerShell script via WinRM and return stdout as a string."""
        result = session.run_ps(script)
        return (result.std_out or b"").decode("utf-8", errors="replace").strip()

    def _check_smb_signing(self) -> List[ConnectorFinding]:
        """Check registry for SMB signing requirement. If disabled → HIGH."""
        findings = []
        try:
            session = self._get_winrm_session()
            if session is None:
                return findings
            script = (
                "(Get-ItemProperty "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' "
                "-Name RequireSecuritySignature -ErrorAction SilentlyContinue)"
                ".RequireSecuritySignature"
            )
            output = self._winrm_ps(session, script)
            if output in ("", "0"):
                findings.append(ConnectorFinding(
                    title="SMB signing not required — vulnerable to NTLM relay attacks",
                    description=(
                        "The registry key HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer"
                        "\\Parameters\\RequireSecuritySignature is 0 (disabled). "
                        "Without SMB signing, an attacker can perform NTLM relay attacks to "
                        "authenticate as another host or user."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_id=self.credentials.get("winrm_host", "unknown"),
                    resource_type="Windows Host",
                    control_id="NIST SC-8",
                    framework="nist_800_53",
                    remediation=(
                        "Enable SMB signing via Group Policy: "
                        "Computer Configuration > Windows Settings > Security Settings > "
                        "Local Policies > Security Options > 'Microsoft network server: "
                        "Digitally sign communications (always)' = Enabled."
                    ),
                    evidence={"RequireSecuritySignature": output or "0"},
                ))
        except Exception as exc:
            logger.warning("_check_smb_signing failed: %s", exc)
        return findings

    def _check_local_admin_count(self) -> List[ConnectorFinding]:
        """Enumerate local Administrators group via PowerShell. If > 3 members → MEDIUM."""
        findings = []
        try:
            session = self._get_winrm_session()
            if session is None:
                return findings
            script = (
                "(Get-LocalGroupMember -Group 'Administrators' "
                "-ErrorAction SilentlyContinue).Count"
            )
            output = self._winrm_ps(session, script)
            try:
                count = int(output)
            except ValueError:
                logger.warning("Could not parse local admin count from: %r", output)
                return findings
            if count > 3:
                # Retrieve names for evidence
                names_script = (
                    "(Get-LocalGroupMember -Group 'Administrators' "
                    "-ErrorAction SilentlyContinue).Name -join ', '"
                )
                names = self._winrm_ps(session, names_script)
                findings.append(ConnectorFinding(
                    title=f"Excessive local Administrators members ({count})",
                    description=(
                        f"The local Administrators group has {count} members, exceeding the "
                        "recommended maximum of 3. Excessive local admin accounts increase "
                        "the blast radius of a compromised credential."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    resource_id=self.credentials.get("winrm_host", "unknown"),
                    resource_type="Windows Host",
                    control_id="NIST AC-6",
                    framework="nist_800_53",
                    remediation=(
                        "Remove unnecessary accounts from the local Administrators group. "
                        "Use the principle of least privilege and manage admin access centrally via AD."
                    ),
                    evidence={"member_count": count, "members": names},
                ))
        except Exception as exc:
            logger.warning("_check_local_admin_count failed: %s", exc)
        return findings

    def _check_audit_policy(self) -> List[ConnectorFinding]:
        """Check Windows audit policy categories. Flag unconfigured critical categories → MEDIUM."""
        findings = []
        try:
            session = self._get_winrm_session()
            if session is None:
                return findings
            script = "auditpol /get /category:* /r | ConvertFrom-Csv | Select-Object 'Subcategory','Inclusion Setting' | ConvertTo-Json"
            output = self._winrm_ps(session, script)
            import json
            try:
                rows = json.loads(output) if output else []
            except Exception:
                rows = []
            # Key subcategories that must not be "No Auditing"
            required = {
                "Logon": False,
                "Account Logon": False,
                "Logoff": False,
                "Privilege Use": False,
                "Object Access": False,
                "Process Creation": False,
            }
            for row in rows:
                subcat = str(row.get("Subcategory", ""))
                setting = str(row.get("Inclusion Setting", "No Auditing"))
                for key in required:
                    if key.lower() in subcat.lower() and setting != "No Auditing":
                        required[key] = True
            not_configured = [k for k, v in required.items() if not v]
            if not_configured:
                findings.append(ConnectorFinding(
                    title=f"Windows audit policy not configured for: {', '.join(not_configured)}",
                    description=(
                        f"The following audit categories are not configured (set to 'No Auditing'): "
                        f"{', '.join(not_configured)}. Without these audit settings, security events "
                        "such as logon failures, privilege use, and object access are not logged."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    resource_id=self.credentials.get("winrm_host", "unknown"),
                    resource_type="Windows Host",
                    control_id="NIST AU-2",
                    framework="nist_800_53",
                    remediation=(
                        "Configure audit policy via Group Policy or auditpol.exe to enable "
                        "Success and Failure auditing for: Account Logon, Logon/Logoff, "
                        "Privilege Use, Object Access, and Process Creation."
                    ),
                    evidence={"not_configured": not_configured},
                ))
        except Exception as exc:
            logger.warning("_check_audit_policy failed: %s", exc)
        return findings

    # ── Linux / SSH checks ──────────────────────────────────────────────────────

    def _get_ssh_client(self):
        """Return a connected paramiko SSHClient or None."""
        try:
            import paramiko
        except ImportError:
            logger.warning("paramiko not installed; skipping SSH-based Linux checks")
            return None
        host = self.credentials.get("ssh_host")
        username = self.credentials.get("ssh_user")
        password = self.credentials.get("ssh_password")
        key_path = self.credentials.get("ssh_key_path")
        if not (host and username):
            return None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            port = int(self.credentials.get("ssh_port", 22))
            if key_path:
                client.connect(host, port=port, username=username, key_filename=key_path, timeout=10)
            else:
                client.connect(host, port=port, username=username, password=password, timeout=10)
            return client
        except Exception as exc:
            logger.warning("SSH connection failed: %s", exc)
            return None

    def _ssh_run(self, client, command: str) -> str:
        """Run a command over SSH and return stdout."""
        try:
            _, stdout, _ = client.exec_command(command, timeout=15)
            return stdout.read().decode("utf-8", errors="replace").strip()
        except Exception as exc:
            logger.warning("SSH command failed (%r): %s", command, exc)
            return ""

    def _check_ssh_config(self) -> List[ConnectorFinding]:
        """Check /etc/ssh/sshd_config for dangerous settings."""
        findings = []
        client = None
        try:
            client = self._get_ssh_client()
            if client is None:
                return findings
            raw = self._ssh_run(client, "cat /etc/ssh/sshd_config 2>/dev/null")
            host = self.credentials.get("ssh_host", "unknown")

            def _get_setting(lines, key):
                for line in lines:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    parts = line.split(None, 1)
                    if parts and parts[0].lower() == key.lower():
                        return parts[1].strip().lower() if len(parts) > 1 else ""
                return None

            lines = raw.splitlines()
            checks = [
                ("PermitRootLogin", "yes", FindingSeverity.CRITICAL,
                 "SSH PermitRootLogin is enabled — direct root login allowed",
                 "Direct root login via SSH exposes the system to brute-force and credential theft targeting the most privileged account.",
                 "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd."),
                ("PermitEmptyPasswords", "yes", FindingSeverity.CRITICAL,
                 "SSH PermitEmptyPasswords is enabled — accounts with no password can log in",
                 "Allowing empty passwords means any account without a password is accessible remotely without authentication.",
                 "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config and restart sshd."),
                ("PasswordAuthentication", "yes", FindingSeverity.HIGH,
                 "SSH PasswordAuthentication is enabled — brute-force risk without MFA",
                 "Password-based SSH authentication without multi-factor authentication is vulnerable to brute-force and credential-stuffing attacks.",
                 "Disable password authentication ('PasswordAuthentication no') and use SSH key-based authentication only."),
            ]
            for setting_key, bad_value, severity, title, description, remediation in checks:
                val = _get_setting(lines, setting_key)
                if val is not None and val == bad_value:
                    findings.append(ConnectorFinding(
                        title=title,
                        description=description,
                        severity=severity,
                        resource_id=host,
                        resource_type="Linux Host",
                        control_id="NIST AC-17",
                        framework="nist_800_53",
                        remediation=remediation,
                        evidence={"setting": setting_key, "value": val, "file": "/etc/ssh/sshd_config"},
                    ))
            # Protocol 1
            proto = _get_setting(lines, "Protocol")
            if proto and "1" in proto:
                findings.append(ConnectorFinding(
                    title="SSH Protocol 1 is enabled — deprecated and insecure",
                    description=(
                        "sshd_config specifies Protocol 1, which uses weak cryptography (DES, RC4) "
                        "and has known vulnerabilities. Protocol 1 should never be used."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_id=host,
                    resource_type="Linux Host",
                    control_id="NIST AC-17",
                    framework="nist_800_53",
                    remediation="Remove 'Protocol 1' from sshd_config (Protocol 2 is the default on modern sshd).",
                    evidence={"Protocol": proto},
                ))
        except Exception as exc:
            logger.warning("_check_ssh_config failed: %s", exc)
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass
        return findings

    def _check_sudoers(self) -> List[ConnectorFinding]:
        """Check for NOPASSWD entries in /etc/sudoers and /etc/sudoers.d/."""
        findings = []
        client = None
        try:
            client = self._get_ssh_client()
            if client is None:
                return findings
            host = self.credentials.get("ssh_host", "unknown")
            # Grep both sudoers files (requires read permission — may need privilege)
            cmd = (
                "sudo grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null "
                "|| grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null"
            )
            raw = self._ssh_run(client, cmd)
            if not raw:
                return findings
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Extract user/alias from the line
                user_part = line.split()[0] if line.split() else line
                findings.append(ConnectorFinding(
                    title=f"Passwordless sudo detected for '{user_part}'",
                    description=(
                        f"A NOPASSWD entry was found in sudoers configuration: {line!r}. "
                        "Passwordless sudo allows privilege escalation without any authentication check."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_id=host,
                    resource_type="Linux Host",
                    control_id="NIST AC-6",
                    framework="nist_800_53",
                    remediation=(
                        "Remove NOPASSWD from sudoers entries. Require password authentication for "
                        "all sudo operations. Use 'visudo' to edit sudoers safely."
                    ),
                    evidence={"sudoers_line": line},
                ))
        except Exception as exc:
            logger.warning("_check_sudoers failed: %s", exc)
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass
        return findings

    def _check_firewall_status(self) -> List[ConnectorFinding]:
        """Check if ufw, firewalld, or iptables is active. If no firewall → HIGH."""
        findings = []
        client = None
        try:
            client = self._get_ssh_client()
            if client is None:
                return findings
            host = self.credentials.get("ssh_host", "unknown")
            # ufw
            ufw_status = self._ssh_run(client, "ufw status 2>/dev/null | head -1")
            if "active" in ufw_status.lower():
                return findings  # firewall active
            # firewalld
            firewalld_status = self._ssh_run(
                client, "systemctl is-active firewalld 2>/dev/null"
            )
            if firewalld_status.strip() == "active":
                return findings
            # iptables — non-empty chain rules mean something is configured
            iptables_rules = self._ssh_run(
                client, "iptables -L INPUT --line-numbers 2>/dev/null | grep -v '^Chain\\|^num\\|^$' | wc -l"
            )
            try:
                if int(iptables_rules) > 0:
                    return findings
            except ValueError:
                pass
            findings.append(ConnectorFinding(
                title="No active host firewall detected (ufw/firewalld/iptables)",
                description=(
                    f"No active firewall was detected on host '{host}'. "
                    "Neither ufw, firewalld, nor iptables rules are active. "
                    "Without a host-based firewall, all network ports are accessible."
                ),
                severity=FindingSeverity.HIGH,
                resource_id=host,
                resource_type="Linux Host",
                control_id="NIST SC-7",
                framework="nist_800_53",
                remediation=(
                    "Enable and configure a host-based firewall. For Ubuntu/Debian: 'ufw enable'. "
                    "For RHEL/CentOS: 'systemctl enable --now firewalld'. "
                    "Apply a default-deny policy and allow only required ports."
                ),
            ))
        except Exception as exc:
            logger.warning("_check_firewall_status failed: %s", exc)
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass
        return findings

    # ── Orchestration ────────────────────────────────────────────────────────────

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        """Run all available configuration checks based on configured credentials."""
        findings: List[ConnectorFinding] = []

        # Active Directory / LDAP checks
        findings.extend(self._check_ad_stale_accounts())
        findings.extend(self._check_ad_privileged_groups())
        findings.extend(self._check_ad_password_policy())
        findings.extend(self._check_ad_guest_account())
        findings.extend(self._check_ad_krbtgt_age())

        # Windows hardening checks (WinRM)
        findings.extend(self._check_smb_signing())
        findings.extend(self._check_local_admin_count())
        findings.extend(self._check_audit_policy())

        # Linux / SSH checks
        findings.extend(self._check_ssh_config())
        findings.extend(self._check_sudoers())
        findings.extend(self._check_firewall_status())

        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        findings = []
        try:
            scans = await self._nessus_get("/scans")
            for scan in scans.get("scans", [])[:5]:
                scan_id = scan["id"]
                detail = await self._nessus_get(f"/scans/{scan_id}")
                for vuln in detail.get("vulnerabilities", []):
                    sev = NESSUS_SEVERITY.get(vuln.get("severity", 0), FindingSeverity.INFO)
                    findings.append(ConnectorFinding(
                        title=vuln.get("plugin_name", ""),
                        description=vuln.get("plugin_name", ""),
                        severity=sev,
                        resource_id=str(scan_id),
                        resource_type="Host",
                        control_id=vuln.get("plugin_id", ""),
                        cve_id=vuln.get("cve", [""])[0] if vuln.get("cve") else "",
                        cvss_score=float(vuln.get("cvss3_base_score", 0) or 0),
                        framework="cve",
                    ))
        except Exception:
            pass
        return findings

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
