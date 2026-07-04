"""
NexGenCyberAI - CyberArk PAM Connector
Security checks against CyberArk Privileged Access Management via REST API.
"""
import logging
import requests
from typing import Any, Dict, List, Optional
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

logger = logging.getLogger(__name__)


class CyberArkConnector(BaseConnector):
    """
    Connects to CyberArk PAS (Privileged Access Security) REST API.

    Required credentials:
        base_url: str  — CyberArk PVWA URL, e.g. https://cyberark.company.com
        username: str  — CyberArk admin username
        password: str  — CyberArk admin password
        auth_type: str — "CyberArk" | "LDAP" | "Windows" (default: "CyberArk")
    """

    def _get_base_url(self) -> str:
        return self.credentials.get("base_url", "").rstrip("/")

    def _get_session_token(self) -> Optional[str]:
        base = self._get_base_url()
        username = self.credentials.get("username", "")
        password = self.credentials.get("password", "")
        auth_type = self.credentials.get("auth_type", "CyberArk")
        try:
            resp = requests.post(
                f"{base}/PasswordVault/API/auth/{auth_type}/Logon",
                json={"username": username, "password": password},
                timeout=15,
                verify=self.config.get("verify_ssl", True),
            )
            resp.raise_for_status()
            return resp.text.strip().strip('"')
        except Exception as exc:
            logger.warning("CyberArk authentication failed: %s", exc)
            return None

    def _api_get(self, token: str, path: str, params: dict = None) -> dict:
        base = self._get_base_url()
        resp = requests.get(
            f"{base}/PasswordVault/API/{path}",
            headers={"Authorization": token},
            params=params or {},
            timeout=15,
            verify=self.config.get("verify_ssl", True),
        )
        resp.raise_for_status()
        return resp.json()

    # ── Connection test ───────────────────────────────────────────────────────

    async def test_connection(self) -> ConnectorTestResult:
        token = self._get_session_token()
        if not token:
            return ConnectorTestResult(success=False, message="Authentication failed. Check PVWA URL, username, and password.")
        try:
            self._api_get(token, "UserGroups?limit=1")
            return ConnectorTestResult(success=True, message="Connected to CyberArk PVWA successfully.", details={"auth": "ok"})
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    # ── Resource inventory ────────────────────────────────────────────────────

    async def get_resources(self) -> List[Dict[str, Any]]:
        token = self._get_session_token()
        if not token:
            return []
        resources = []
        try:
            safes = self._api_get(token, "Safes?limit=100")
            for s in (safes.get("value") or safes.get("Safes") or []):
                resources.append({
                    "id": s.get("safeUrlId") or s.get("SafeName"),
                    "name": s.get("safeName") or s.get("SafeName"),
                    "type": "CyberArk/Safe",
                    "location": s.get("location") or "",
                    "tags": {},
                })
        except Exception as exc:
            logger.debug("CyberArk get_resources failed: %s", exc)
        return resources

    # ── Checks ─────────────────────────────────────────────────────────────────

    def _check_safe_permissions(self, token: str) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        try:
            safes = self._api_get(token, "Safes?limit=500")
            safe_list = safes.get("value") or safes.get("Safes") or []
            for safe in safe_list:
                safe_name = safe.get("safeName") or safe.get("SafeName") or ""
                safe_id = safe.get("safeUrlId") or safe_name
                try:
                    members = self._api_get(token, f"Safes/{safe_id}/Members?limit=100")
                    member_list = members.get("value") or members.get("members") or []
                    for m in member_list:
                        perms = m.get("permissions") or {}
                        name = m.get("memberName") or m.get("MemberName") or ""
                        mtype = (m.get("memberType") or "").lower()
                        # Flag if non-admin user has manageSafe or manageSafeMembers
                        if perms.get("manageSafe") or perms.get("manageSafeMembers"):
                            if mtype == "user":
                                findings.append(ConnectorFinding(
                                    title=f"Safe '{safe_name}': user '{name}' has Manage Safe permissions",
                                    description=f"User '{name}' has ManageSafe/ManageSafeMembers on '{safe_name}'. This allows them to modify safe membership and permissions — a high-privilege action that should be restricted to vault admins.",
                                    severity=FindingSeverity.HIGH,
                                    resource_id=safe_id,
                                    resource_type="CyberArk/Safe",
                                    control_id="NIST AC-6",
                                    remediation=f"Review whether user '{name}' requires Manage Safe permissions on '{safe_name}'. Remove if not justified.",
                                    framework="nist",
                                ))
                except Exception:
                    pass
        except Exception as exc:
            logger.warning("CyberArk safe permissions check failed: %s", exc)
        return findings

    def _check_accounts_last_changed(self, token: str) -> List[ConnectorFinding]:
        """Flag privileged accounts whose passwords have not been rotated recently."""
        findings: List[ConnectorFinding] = []
        try:
            accounts = self._api_get(token, "Accounts?limit=500&filter=safeName ne 'System'")
            account_list = accounts.get("value") or accounts.get("accounts") or []
            for acc in account_list:
                acc_id = acc.get("id") or ""
                acc_name = acc.get("name") or acc.get("userName") or acc_id
                safe_name = acc.get("safeName") or ""
                last_changed = acc.get("secretManagement", {}).get("lastModifiedTime") or 0
                if last_changed:
                    import time
                    days_since = (time.time() - last_changed) / 86400
                    if days_since > 365:
                        findings.append(ConnectorFinding(
                            title=f"Privileged account '{acc_name}' in safe '{safe_name}' — password not rotated in 365+ days",
                            description=f"The credential for '{acc_name}' has not been changed in over 365 days. Long-lived privileged credentials are a high-value target and may be compromised without detection.",
                            severity=FindingSeverity.HIGH,
                            resource_id=acc_id,
                            resource_type="CyberArk/Account",
                            control_id="NIST IA-5",
                            remediation="Enable automatic credential rotation (CPM) for this account, or manually rotate the credential.",
                            framework="nist",
                        ))
                    elif days_since > 180:
                        findings.append(ConnectorFinding(
                            title=f"Privileged account '{acc_name}' in safe '{safe_name}' — password not rotated in 180+ days",
                            description=f"The credential for '{acc_name}' has not been changed in over 180 days.",
                            severity=FindingSeverity.MEDIUM,
                            resource_id=acc_id,
                            resource_type="CyberArk/Account",
                            control_id="NIST IA-5",
                            remediation="Enable CPM automatic rotation or rotate the credential manually.",
                            framework="nist",
                        ))
                # Flag accounts with CPM management disabled
                cpm_status = acc.get("secretManagement", {}).get("automaticManagementEnabled")
                if cpm_status is False:
                    findings.append(ConnectorFinding(
                        title=f"Privileged account '{acc_name}' has automatic credential rotation disabled",
                        description=f"CPM (Central Policy Manager) automatic rotation is disabled for '{acc_name}' in safe '{safe_name}'. The password is managed manually, creating rotation blind spots.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=acc_id,
                        resource_type="CyberArk/Account",
                        control_id="NIST IA-5",
                        remediation="Enable CPM automatic management for this account and associate it with a platform policy that enforces rotation intervals.",
                        framework="nist",
                    ))
        except Exception as exc:
            logger.warning("CyberArk account rotation check failed: %s", exc)
        return findings

    def _check_user_accounts(self, token: str) -> List[ConnectorFinding]:
        """Check for CyberArk vault users with excessive permissions or risky settings."""
        findings: List[ConnectorFinding] = []
        try:
            users = self._api_get(token, "Users?limit=200")
            user_list = users.get("Users") or users.get("value") or []
            for u in user_list:
                uid = str(u.get("id") or "")
                uname = u.get("username") or uid
                # Flag built-in admin if not expected
                if uname.lower() in ("administrator", "admin", "vault"):
                    findings.append(ConnectorFinding(
                        title=f"CyberArk built-in vault user '{uname}' is active",
                        description=f"The built-in vault administrator account '{uname}' is active. Built-in accounts should be disabled after initial setup and replaced with named admin accounts for accountability.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=uid,
                        resource_type="CyberArk/User",
                        control_id="NIST AC-2",
                        remediation=f"Disable the built-in '{uname}' account and use named vault administrator accounts with individual credentials.",
                        framework="nist",
                    ))
        except Exception as exc:
            logger.warning("CyberArk user check failed: %s", exc)
        return findings

    def _check_session_recording(self, token: str) -> List[ConnectorFinding]:
        """Check for safes that contain privileged sessions without PSM recording configured."""
        findings: List[ConnectorFinding] = []
        try:
            platforms = self._api_get(token, "Platforms?Active=true")
            platform_list = platforms.get("Platforms") or platforms.get("value") or []
            for p in platform_list:
                pid = p.get("general", {}).get("id") or p.get("ID") or str(p.get("id") or "")
                pname = p.get("general", {}).get("name") or p.get("Name") or pid
                # Check if PSM is configured
                psm = p.get("privilegedSessionManagement") or {}
                if not psm.get("psmpServerID") and not psm.get("PSMServerId"):
                    findings.append(ConnectorFinding(
                        title=f"CyberArk platform '{pname}' has no PSM session recording configured",
                        description=f"Platform '{pname}' does not have Privileged Session Management (PSM) configured. Privileged sessions using this platform are not recorded or auditable.",
                        severity=FindingSeverity.HIGH,
                        resource_id=pid,
                        resource_type="CyberArk/Platform",
                        control_id="NIST AU-12",
                        remediation="Configure PSM server for this platform to enable session recording and auditing of all privileged access.",
                        framework="nist",
                    ))
        except Exception as exc:
            logger.warning("CyberArk PSM check failed: %s", exc)
        return findings

    # ── Public scan methods ───────────────────────────────────────────────────

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        token = self._get_session_token()
        if not token:
            logger.warning("CyberArk: could not authenticate — skipping configuration review")
            return []
        findings: List[ConnectorFinding] = []
        findings += self._check_safe_permissions(token)
        findings += self._check_accounts_last_changed(token)
        findings += self._check_user_accounts(token)
        findings += self._check_session_recording(token)
        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []  # CyberArk has no vulnerability scan — all checks are configuration

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
