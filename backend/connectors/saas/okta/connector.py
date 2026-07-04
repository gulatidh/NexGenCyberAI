"""
NexGenCyberAI - Okta Identity Provider Connector
Security checks against Okta via Okta Management API.
"""
import logging
import requests
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

logger = logging.getLogger(__name__)


class OktaConnector(BaseConnector):
    """
    Connects to Okta via Okta Management API.

    Required credentials:
        domain: str      — Okta domain, e.g. https://company.okta.com
        api_token: str   — Okta API token (SSWS token)
    """

    def _get_domain(self) -> str:
        return self.credentials.get("domain", "").rstrip("/")

    def _headers(self) -> dict:
        return {
            "Authorization": f"SSWS {self.credentials.get('api_token', '')}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _api_get(self, path: str, params: dict = None):
        domain = self._get_domain()
        resp = requests.get(
            f"{domain}/api/v1/{path}",
            headers=self._headers(),
            params=params or {},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def _paginate(self, path: str, limit: int = 200) -> list:
        """Fetch all pages from an Okta paginated endpoint."""
        domain = self._get_domain()
        url = f"{domain}/api/v1/{path}?limit={limit}"
        results = []
        while url:
            resp = requests.get(url, headers=self._headers(), timeout=15)
            resp.raise_for_status()
            results.extend(resp.json())
            # Okta uses Link header for pagination
            next_link = None
            for link in (resp.headers.get("Link") or "").split(","):
                if 'rel="next"' in link:
                    next_link = link.strip().split(";")[0].strip("<>")
            url = next_link
            if len(results) >= 2000:  # safety cap
                break
        return results

    # ── Connection test ───────────────────────────────────────────────────────

    async def test_connection(self) -> ConnectorTestResult:
        try:
            info = self._api_get("org")
            return ConnectorTestResult(
                success=True,
                message=f"Connected to Okta org: {info.get('companyName', 'unknown')}",
                details={"org": info.get("companyName")},
            )
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    # ── Resource inventory ────────────────────────────────────────────────────

    async def get_resources(self) -> List[Dict[str, Any]]:
        resources = []
        try:
            users = self._paginate("users")
            for u in users:
                profile = u.get("profile") or {}
                resources.append({
                    "id": u.get("id"),
                    "name": profile.get("displayName") or profile.get("login"),
                    "type": "Okta/User",
                    "status": u.get("status"),
                    "tags": {},
                })
        except Exception as exc:
            logger.debug("Okta get_resources failed: %s", exc)
        return resources

    # ── Checks ─────────────────────────────────────────────────────────────────

    def _check_mfa_enrollment(self) -> List[ConnectorFinding]:
        """Check for active users with no MFA factors enrolled."""
        findings: List[ConnectorFinding] = []
        try:
            users = self._paginate("users?filter=status eq \"ACTIVE\"")
            no_mfa_count = 0
            no_mfa_examples = []
            for u in users:
                uid = u.get("id", "")
                profile = u.get("profile") or {}
                login = profile.get("login") or uid
                try:
                    factors = self._api_get(f"users/{uid}/factors")
                    if not factors:
                        no_mfa_count += 1
                        if len(no_mfa_examples) < 5:
                            no_mfa_examples.append(login)
                except Exception:
                    pass
            if no_mfa_count > 0:
                sev = FindingSeverity.CRITICAL if no_mfa_count > 50 else FindingSeverity.HIGH
                findings.append(ConnectorFinding(
                    title=f"{no_mfa_count} active Okta users have no MFA factor enrolled",
                    description=f"{no_mfa_count} active users have no MFA method enrolled. Examples: {', '.join(no_mfa_examples)}. These accounts rely solely on password for authentication.",
                    severity=sev,
                    resource_id="okta/users",
                    resource_type="Okta/User",
                    control_id="NIST IA-2",
                    remediation="Enforce MFA enrollment for all users via Okta Sign-On Policy or Okta Identity Engine authenticator enrollment policies.",
                    framework="nist",
                ))
        except Exception as exc:
            logger.warning("Okta MFA enrollment check failed: %s", exc)
        return findings

    def _check_password_policy(self) -> List[ConnectorFinding]:
        """Check Okta password policies for weak settings."""
        findings: List[ConnectorFinding] = []
        try:
            policies = self._api_get("policies?type=PASSWORD")
            for policy in (policies if isinstance(policies, list) else []):
                pid = policy.get("id", "")
                pname = policy.get("name", pid)
                settings = policy.get("settings") or {}
                pw = settings.get("password") or {}
                complexity = pw.get("complexity") or {}

                min_len = complexity.get("minLength") or 0
                if min_len < 12:
                    findings.append(ConnectorFinding(
                        title=f"Okta password policy '{pname}' requires fewer than 12 characters",
                        description=f"Password policy '{pname}' has a minimum length of {min_len}. NIST SP 800-63B recommends at least 12 characters for memorized secrets.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=pid,
                        resource_type="Okta/PasswordPolicy",
                        control_id="NIST IA-5",
                        remediation="Update the password policy to require a minimum of 12 characters.",
                        framework="nist",
                    ))

                lockout = settings.get("lockout") or {}
                max_attempts = lockout.get("maxAttempts") or 0
                if max_attempts == 0 or max_attempts > 10:
                    findings.append(ConnectorFinding(
                        title=f"Okta password policy '{pname}' has no effective account lockout",
                        description=f"Policy '{pname}' allows {max_attempts or 'unlimited'} failed attempts before lockout. This enables password brute-force attacks.",
                        severity=FindingSeverity.HIGH,
                        resource_id=pid,
                        resource_type="Okta/PasswordPolicy",
                        control_id="NIST AC-7",
                        remediation="Set lockout threshold to 5-10 failed attempts in the password policy.",
                        framework="nist",
                    ))
        except Exception as exc:
            logger.warning("Okta password policy check failed: %s", exc)
        return findings

    def _check_inactive_users(self) -> List[ConnectorFinding]:
        """Flag users who haven't logged in for 90+ days."""
        findings: List[ConnectorFinding] = []
        try:
            threshold_90 = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
            users = self._paginate(f"users?filter=status eq \"ACTIVE\" and lastLogin lt \"{threshold_90}\"")
            stale_90 = []
            stale_180 = []
            cutoff_180 = datetime.now(timezone.utc) - timedelta(days=180)
            for u in users:
                profile = u.get("profile") or {}
                login = profile.get("login") or u.get("id")
                last_login_str = u.get("lastLogin")
                if last_login_str:
                    try:
                        last_login = datetime.fromisoformat(last_login_str.replace("Z", "+00:00"))
                        if last_login < cutoff_180:
                            stale_180.append(login)
                        else:
                            stale_90.append(login)
                    except Exception:
                        stale_90.append(login)
                else:
                    stale_90.append(login)
            if stale_180:
                findings.append(ConnectorFinding(
                    title=f"{len(stale_180)} active Okta users have not logged in for 180+ days",
                    description=f"{len(stale_180)} enabled user accounts have had no login activity for over 180 days. Examples: {', '.join(stale_180[:5])}. These are likely orphaned accounts.",
                    severity=FindingSeverity.HIGH,
                    resource_id="okta/users",
                    resource_type="Okta/User",
                    control_id="NIST AC-2",
                    remediation="Deactivate or remove accounts with no login activity for 180+ days. Implement a periodic access review process.",
                    framework="nist",
                ))
            if stale_90:
                findings.append(ConnectorFinding(
                    title=f"{len(stale_90)} active Okta users have not logged in for 90+ days",
                    description=f"{len(stale_90)} enabled accounts have had no login activity for 90-180 days. Examples: {', '.join(stale_90[:5])}.",
                    severity=FindingSeverity.MEDIUM,
                    resource_id="okta/users",
                    resource_type="Okta/User",
                    control_id="NIST AC-2",
                    remediation="Review and deactivate accounts inactive for 90+ days. Consider automated deprovisioning via Okta Lifecycle Management.",
                    framework="nist",
                ))
        except Exception as exc:
            logger.warning("Okta inactive user check failed: %s", exc)
        return findings

    def _check_admin_users(self) -> List[ConnectorFinding]:
        """Check for excessive admin assignments."""
        findings: List[ConnectorFinding] = []
        try:
            admins = self._paginate("users?filter=profile.userType eq \"SUPER_OKTA_ADMIN\"")
            if len(admins) > 5:
                logins = [u.get("profile", {}).get("login") or u.get("id") for u in admins[:10]]
                findings.append(ConnectorFinding(
                    title=f"Okta has {len(admins)} Super Administrators — excessive privilege",
                    description=f"{len(admins)} users hold Super Administrator in Okta. Examples: {', '.join(logins)}. Super Admins can modify any Okta configuration including MFA and sign-on policies.",
                    severity=FindingSeverity.HIGH,
                    resource_id="okta/admins",
                    resource_type="Okta/User",
                    control_id="NIST AC-6",
                    remediation="Reduce Super Admin count to 2-3 break-glass accounts. Use scoped roles (Application Admin, Group Admin) for day-to-day operations.",
                    framework="nist",
                ))
        except Exception as exc:
            logger.warning("Okta admin check failed: %s", exc)
        return findings

    def _check_sign_on_policies(self) -> List[ConnectorFinding]:
        """Check Okta sign-on policies for gaps like no MFA requirement."""
        findings: List[ConnectorFinding] = []
        try:
            policies = self._api_get("policies?type=OKTA_SIGN_ON")
            for policy in (policies if isinstance(policies, list) else []):
                pid = policy.get("id", "")
                pname = policy.get("name", pid)
                try:
                    rules = self._api_get(f"policies/{pid}/rules")
                    for rule in (rules if isinstance(rules, list) else []):
                        rname = rule.get("name", "")
                        actions = rule.get("actions") or {}
                        signon = actions.get("signon") or {}
                        # Check if any rule allows access without MFA
                        if signon.get("requireFactor") is False and signon.get("access") == "ALLOW":
                            findings.append(ConnectorFinding(
                                title=f"Okta sign-on policy '{pname}' rule '{rname}' allows login without MFA",
                                description=f"Sign-on policy '{pname}', rule '{rname}' allows access without MFA factor verification. Users matching this rule can authenticate with password only.",
                                severity=FindingSeverity.HIGH,
                                resource_id=pid,
                                resource_type="Okta/SignOnPolicy",
                                control_id="NIST IA-2",
                                remediation=f"Update rule '{rname}' to require MFA, or restrict access for users matching this rule.",
                                framework="nist",
                            ))
                except Exception:
                    pass
        except Exception as exc:
            logger.warning("Okta sign-on policy check failed: %s", exc)
        return findings

    def _check_api_tokens(self) -> List[ConnectorFinding]:
        """Check for long-lived Okta API tokens."""
        findings: List[ConnectorFinding] = []
        try:
            tokens = self._api_get("api-tokens")
            token_list = tokens if isinstance(tokens, list) else tokens.get("value", [])
            old_tokens = []
            cutoff = datetime.now(timezone.utc) - timedelta(days=90)
            for t in token_list:
                created_str = t.get("created") or ""
                name = t.get("name") or t.get("id") or "unknown"
                if created_str:
                    try:
                        created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                        if created < cutoff:
                            old_tokens.append(name)
                    except Exception:
                        pass
            if old_tokens:
                findings.append(ConnectorFinding(
                    title=f"{len(old_tokens)} Okta API tokens are older than 90 days",
                    description=f"Long-lived API tokens: {', '.join(old_tokens[:5])}. Long-lived tokens increase the window of opportunity for a stolen token to be misused.",
                    severity=FindingSeverity.MEDIUM,
                    resource_id="okta/api-tokens",
                    resource_type="Okta/APIToken",
                    control_id="NIST IA-5",
                    remediation="Rotate API tokens older than 90 days. Consider using OAuth 2.0 service-to-service flows instead of static API tokens.",
                    framework="nist",
                ))
        except Exception as exc:
            logger.warning("Okta API token check failed: %s", exc)
        return findings

    def _check_threat_insights(self) -> List[ConnectorFinding]:
        """Check Okta ThreatInsight configuration."""
        findings: List[ConnectorFinding] = []
        try:
            ti = self._api_get("threats/configuration")
            action = (ti.get("action") or "").lower()
            if action in ("none", ""):
                findings.append(ConnectorFinding(
                    title="Okta ThreatInsight is not configured to block risky IPs",
                    description="ThreatInsight action is set to 'none' or is unconfigured. Okta's threat intelligence feed will not block or challenge logins from known-malicious IP addresses.",
                    severity=FindingSeverity.MEDIUM,
                    resource_id="okta/threats/configuration",
                    resource_type="Okta/ThreatInsight",
                    control_id="NIST SI-3",
                    remediation="Set ThreatInsight to 'audit' at minimum, or 'block' to automatically block login attempts from IP addresses with a history of malicious activity.",
                    framework="nist",
                ))
        except Exception as exc:
            logger.warning("Okta ThreatInsight check failed: %s", exc)
        return findings

    # ── Public scan methods ───────────────────────────────────────────────────

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        findings += self._check_mfa_enrollment()
        findings += self._check_password_policy()
        findings += self._check_inactive_users()
        findings += self._check_admin_users()
        findings += self._check_sign_on_policies()
        findings += self._check_api_tokens()
        findings += self._check_threat_insights()
        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
