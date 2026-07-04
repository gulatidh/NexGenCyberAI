"""
NexGenCyberAI - Entra ID (Azure AD) Connector
Reads identity posture: MFA status, risky users, risky sign-ins,
conditional access policies, privileged accounts.
Uses Microsoft Graph API via MSAL client credentials.
"""
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List
import httpx
import msal
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity


GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

# Privileged roles to scrutinise
_PRIVILEGED_ROLE_NAMES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
}


class EntraIDConnector(BaseConnector):

    def _get_token(self) -> str:
        app = msal.ConfidentialClientApplication(
            client_id=self.credentials["client_id"],
            client_credential=self.credentials["client_secret"],
            authority=f"https://login.microsoftonline.com/{self.credentials['tenant_id']}",
        )
        result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        if "access_token" not in result:
            raise ValueError(f"MSAL error: {result.get('error_description')}")
        return result["access_token"]

    async def _graph_get(self, path: str, beta: bool = False) -> Dict:
        token = self._get_token()
        base = GRAPH_BETA if beta else GRAPH_BASE
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{base}{path}",
                headers={"Authorization": f"Bearer {token}"},
            )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_dt(self, value: str | None) -> datetime | None:
        """Parse an ISO-8601 datetime string returned by Graph API."""
        if not value:
            return None
        try:
            # Graph returns values like "2024-03-01T10:00:00Z"
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # Connection / resource helpers
    # ------------------------------------------------------------------

    async def test_connection(self) -> ConnectorTestResult:
        try:
            data = await self._graph_get("/organization")
            org = data.get("value", [{}])[0]
            return ConnectorTestResult(
                success=True,
                message=f"Connected to tenant: {org.get('displayName', 'Unknown')}",
                details={"tenant_id": org.get("id"), "display_name": org.get("displayName")},
            )
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    async def get_resources(self) -> List[Dict[str, Any]]:
        data = await self._graph_get("/users?$top=100&$select=id,displayName,userPrincipalName,accountEnabled")
        return data.get("value", [])

    # ------------------------------------------------------------------
    # Configuration review entry point
    # ------------------------------------------------------------------

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []

        # --- Original checks ---

        # Check for users without MFA
        try:
            data = await self._graph_get(
                "/reports/authenticationMethods/userRegistrationDetails?$top=100", beta=True
            )
            for user in data.get("value", []):
                if not user.get("isMfaRegistered"):
                    findings.append(ConnectorFinding(
                        title="User not registered for MFA",
                        description=f"{user.get('userPrincipalName')} has no MFA registration.",
                        severity=FindingSeverity.HIGH,
                        resource_id=user.get("id", ""),
                        resource_type="EntraID User",
                        control_id="NIST IA-2",
                        framework="nist_csf",
                        remediation="Enforce MFA registration via Conditional Access policy.",
                    ))
        except Exception:
            pass

        # Risky users
        try:
            data = await self._graph_get("/identityProtection/riskyUsers?$filter=riskLevel ne 'none'", beta=True)
            for user in data.get("value", []):
                sev = FindingSeverity.HIGH if user.get("riskLevel") in ("high", "medium") else FindingSeverity.LOW
                findings.append(ConnectorFinding(
                    title="Risky user detected",
                    description=f"{user.get('userPrincipalName')} — risk level: {user.get('riskLevel')}",
                    severity=sev,
                    resource_id=user.get("id", ""),
                    resource_type="EntraID User",
                    control_id="NIST AC-2",
                    framework="nist_csf",
                ))
        except Exception:
            pass

        # Conditional Access - check for legacy auth allowance
        try:
            data = await self._graph_get("/identity/conditionalAccess/policies", beta=True)
            blocks_legacy = any(
                "exchangeActiveSync" in str(p.get("conditions", {}).get("clientAppTypes", []))
                for p in data.get("value", [])
            )
            if not blocks_legacy:
                findings.append(ConnectorFinding(
                    title="Legacy authentication not blocked by Conditional Access",
                    description="No Conditional Access policy found blocking legacy auth protocols.",
                    severity=FindingSeverity.HIGH,
                    resource_type="Conditional Access",
                    control_id="NIST AC-17",
                    framework="nist_csf",
                    remediation="Create a CA policy to block legacy authentication clients.",
                ))
        except Exception:
            pass

        # --- New identity security checks ---
        findings.extend(await self._check_mfa_policy())
        findings.extend(await self._check_guest_users())
        findings.extend(await self._check_stale_users())
        findings.extend(await self._check_privileged_roles())
        findings.extend(await self._check_app_registrations())
        findings.extend(await self._check_password_policy())

        return findings

    # ------------------------------------------------------------------
    # New checks
    # ------------------------------------------------------------------

    async def _check_mfa_policy(self) -> List[ConnectorFinding]:
        """
        Verify that a Conditional Access policy enforces MFA for all users.
        Falls back to checking per-user MFA state if no CA policy is found.
        NIST IA-2 | resource_type: Microsoft.AzureAD/policies
        """
        findings: List[ConnectorFinding] = []
        try:
            # Fetch CA policies (v1.0 endpoint)
            ca_data = await self._graph_get("/identity/conditionalAccess/policies")
            policies = ca_data.get("value", [])

            # A policy enforces MFA for all users when:
            #   - includeUsers contains "All"  (or no excludeUsers list, but "All" is the reliable signal)
            #   - grantControls requires "mfa"
            def _enforces_mfa_for_all(policy: Dict) -> bool:
                if policy.get("state") != "enabled":
                    return False
                include_users = policy.get("conditions", {}).get("users", {}).get("includeUsers", [])
                grant = policy.get("grantControls") or {}
                built_in = grant.get("builtInControls", [])
                return "All" in include_users and "mfa" in built_in

            has_all_user_mfa_ca = any(_enforces_mfa_for_all(p) for p in policies)

            if not has_all_user_mfa_ca:
                findings.append(ConnectorFinding(
                    title="No Conditional Access policy enforcing MFA for all users",
                    description=(
                        "No enabled Conditional Access policy was found that requires "
                        "multi-factor authentication for all users. Accounts are vulnerable "
                        "to credential-based attacks."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    resource_type="Microsoft.AzureAD/policies",
                    control_id="NIST IA-2",
                    framework="nist_csf",
                    remediation=(
                        "Create a Conditional Access policy that targets all users and all cloud apps "
                        "with a grant control requiring MFA. Use report-only mode first to assess impact."
                    ),
                ))

                # Additionally check whether legacy per-user MFA is in use
                try:
                    users_data = await self._graph_get(
                        "/users?$select=id,userPrincipalName,strongAuthenticationDetail", beta=True
                    )
                    per_user_mfa_count = sum(
                        1 for u in users_data.get("value", [])
                        if u.get("strongAuthenticationDetail", {}).get("methods")
                    )
                    if per_user_mfa_count > 0:
                        findings.append(ConnectorFinding(
                            title="MFA is configured per-user only, not via Conditional Access",
                            description=(
                                f"{per_user_mfa_count} user(s) have per-user MFA enabled but no "
                                "Conditional Access policy enforces MFA globally. Per-user MFA is "
                                "a legacy approach that is harder to manage and audit."
                            ),
                            severity=FindingSeverity.HIGH,
                            resource_type="Microsoft.AzureAD/policies",
                            control_id="NIST IA-2",
                            framework="nist_csf",
                            remediation=(
                                "Migrate from per-user MFA to a Conditional Access policy. "
                                "Disable per-user MFA state after the CA policy is enforced."
                            ),
                        ))
                except Exception:
                    pass  # perUserMfaState requires additional permissions; skip gracefully
        except Exception:
            pass
        return findings

    async def _check_guest_users(self) -> List[ConnectorFinding]:
        """
        Audit guest (external) users for count and inactivity.
        NIST AC-2 | resource_type: Microsoft.AzureAD/users
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get(
                "/users?$filter=userType eq 'Guest'"
                "&$select=id,displayName,mail,userPrincipalName,signInActivity,createdDateTime"
            )
            guests = data.get("value", [])
            count = len(guests)

            if count > 50:
                findings.append(ConnectorFinding(
                    title=f"Entra ID has {count} guest users — review external access",
                    description=(
                        f"The tenant contains {count} guest (external) users. "
                        "A large number of guests increases the attack surface and may indicate "
                        "uncontrolled external collaboration."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    resource_type="Microsoft.AzureAD/users",
                    control_id="NIST AC-2",
                    framework="nist_csf",
                    remediation=(
                        "Review all guest accounts. Remove guests who no longer require access. "
                        "Implement an access review policy in Entra ID Governance."
                    ),
                ))

            now = datetime.now(timezone.utc)
            threshold_90 = now - timedelta(days=90)

            for guest in guests:
                mail = guest.get("mail") or guest.get("userPrincipalName") or guest.get("id")
                sign_in_activity = guest.get("signInActivity") or {}
                last_sign_in_str = sign_in_activity.get("lastSignInDateTime")
                last_sign_in = self._parse_dt(last_sign_in_str)

                # Only flag if we have sign-in data and it is stale
                if last_sign_in and last_sign_in < threshold_90:
                    days_inactive = (now - last_sign_in).days
                    findings.append(ConnectorFinding(
                        title=f"Guest user '{mail}' has not signed in for over 90 days — consider removal",
                        description=(
                            f"Guest user '{mail}' last signed in {days_inactive} days ago "
                            f"({last_sign_in.date()}). Inactive guest accounts represent unnecessary "
                            "access that should be revoked."
                        ),
                        severity=FindingSeverity.LOW,
                        resource_id=guest.get("id", ""),
                        resource_type="Microsoft.AzureAD/users",
                        control_id="NIST AC-2",
                        framework="nist_csf",
                        remediation=(
                            f"Review and remove the guest account for '{mail}' or extend an access "
                            "review invitation. Use Entra ID Access Reviews to automate this process."
                        ),
                    ))
        except Exception:
            pass  # signInActivity requires AuditLog.Read.All — handle gracefully
        return findings

    async def _check_stale_users(self) -> List[ConnectorFinding]:
        """
        Detect enabled internal user accounts with no recent sign-in activity.
        NIST AC-2 | resource_type: Microsoft.AzureAD/users
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get(
                "/users?$select=id,displayName,userPrincipalName,signInActivity,accountEnabled"
            )
            users = data.get("value", [])
            now = datetime.now(timezone.utc)
            threshold_90 = now - timedelta(days=90)
            threshold_180 = now - timedelta(days=180)

            for user in users:
                if not user.get("accountEnabled"):
                    continue  # Already disabled — skip

                upn = user.get("userPrincipalName", user.get("id", ""))
                sign_in_activity = user.get("signInActivity") or {}
                last_sign_in_str = sign_in_activity.get("lastSignInDateTime")
                last_sign_in = self._parse_dt(last_sign_in_str)

                if last_sign_in is None:
                    continue  # No sign-in data available (permissions or new account)

                days_inactive = (now - last_sign_in).days

                if last_sign_in < threshold_180:
                    findings.append(ConnectorFinding(
                        title=f"User '{upn}' has not signed in for 180+ days — should be disabled or reviewed",
                        description=(
                            f"Enabled user account '{upn}' has not signed in for {days_inactive} days "
                            f"(last sign-in: {last_sign_in.date()}). Accounts dormant for 180+ days "
                            "pose a significant risk if compromised."
                        ),
                        severity=FindingSeverity.HIGH,
                        resource_id=user.get("id", ""),
                        resource_type="Microsoft.AzureAD/users",
                        control_id="NIST AC-2",
                        framework="nist_csf",
                        remediation=(
                            f"Disable or delete the account for '{upn}'. Confirm with the user's "
                            "manager whether the account is still required. Use Entra ID Access "
                            "Reviews to automate periodic account certification."
                        ),
                    ))
                elif last_sign_in < threshold_90:
                    findings.append(ConnectorFinding(
                        title=f"User '{upn}' has not signed in for 90+ days — account may be stale",
                        description=(
                            f"Enabled user account '{upn}' has not signed in for {days_inactive} days "
                            f"(last sign-in: {last_sign_in.date()}). This may indicate a leaver whose "
                            "account was not deprovisioned."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        resource_id=user.get("id", ""),
                        resource_type="Microsoft.AzureAD/users",
                        control_id="NIST AC-2",
                        framework="nist_csf",
                        remediation=(
                            f"Review the account for '{upn}'. If the user has left the organisation "
                            "or no longer requires access, disable or remove the account."
                        ),
                    ))
        except Exception:
            pass  # signInActivity requires AuditLog.Read.All — handle gracefully
        return findings

    async def _check_privileged_roles(self) -> List[ConnectorFinding]:
        """
        Audit membership of high-privilege directory roles.
        NIST AC-6 | resource_type: Microsoft.AzureAD/directoryRoles
        """
        findings: List[ConnectorFinding] = []
        try:
            roles_data = await self._graph_get("/directoryRoles")
            roles = roles_data.get("value", [])

            for role in roles:
                role_name = role.get("displayName", "")
                if role_name not in _PRIVILEGED_ROLE_NAMES:
                    continue

                role_id = role.get("id", "")
                try:
                    members_data = await self._graph_get(f"/directoryRoles/{role_id}/members")
                    members = members_data.get("value", [])
                except Exception:
                    continue

                member_count = len(members)
                if member_count > 5:
                    findings.append(ConnectorFinding(
                        title=f"Entra ID role '{role_name}' has {member_count} members — excessive privileged access",
                        description=(
                            f"The '{role_name}' role has {member_count} members. "
                            "Microsoft recommends fewer than 5 Global Administrators and similar "
                            "constraints for other privileged roles to minimise the blast radius of "
                            "a compromised privileged account."
                        ),
                        severity=FindingSeverity.HIGH,
                        resource_id=role_id,
                        resource_type="Microsoft.AzureAD/directoryRoles",
                        control_id="NIST AC-6",
                        framework="nist_csf",
                        remediation=(
                            f"Review all members of '{role_name}'. Remove accounts that do not "
                            "require this level of privilege. Use Entra ID Privileged Identity "
                            "Management (PIM) for just-in-time access."
                        ),
                    ))

                for member in members:
                    mail = member.get("mail") or member.get("userPrincipalName") or member.get("id", "")
                    upn = member.get("userPrincipalName") or ""
                    user_type = member.get("userType", "")

                    # Guest in a privileged role
                    if user_type == "Guest":
                        findings.append(ConnectorFinding(
                            title=f"Guest user '{mail}' holds privileged role '{role_name}'",
                            description=(
                                f"External (guest) user '{mail}' is a member of the highly privileged "
                                f"'{role_name}' role. External accounts should never hold "
                                "administrative roles."
                            ),
                            severity=FindingSeverity.CRITICAL,
                            resource_id=member.get("id", ""),
                            resource_type="Microsoft.AzureAD/directoryRoles",
                            control_id="NIST AC-6",
                            framework="nist_csf",
                            remediation=(
                                f"Immediately remove '{mail}' from the '{role_name}' role. "
                                "Investigate how the guest account obtained this assignment."
                            ),
                        ))

                    # Service account in a privileged role
                    upn_lower = upn.lower()
                    if "svc" in upn_lower or "service" in upn_lower:
                        findings.append(ConnectorFinding(
                            title=f"Service account '{upn}' holds privileged role '{role_name}' — use managed identity instead",
                            description=(
                                f"The service account '{upn}' holds the '{role_name}' role. "
                                "Service accounts with permanent privileged access are high-risk; "
                                "a compromise grants persistent administrative control."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            resource_id=member.get("id", ""),
                            resource_type="Microsoft.AzureAD/directoryRoles",
                            control_id="NIST AC-6",
                            framework="nist_csf",
                            remediation=(
                                f"Replace the service account '{upn}' with an Azure Managed Identity "
                                "or a Workload Identity. Remove the account from the privileged role."
                            ),
                        ))
        except Exception:
            pass
        return findings

    async def _check_app_registrations(self) -> List[ConnectorFinding]:
        """
        Review app registrations for expired/long-lived secrets and missing cert auth.
        NIST IA-5 | resource_type: Microsoft.AzureAD/applications
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get(
                "/applications?$select=id,displayName,appId,passwordCredentials,keyCredentials,createdDateTime"
            )
            apps = data.get("value", [])
            now = datetime.now(timezone.utc)

            for app in apps:
                name = app.get("displayName", app.get("appId", "unknown"))
                password_creds = app.get("passwordCredentials") or []
                key_creds = app.get("keyCredentials") or []

                for cred in password_creds:
                    end_dt = self._parse_dt(cred.get("endDateTime"))
                    start_dt = self._parse_dt(cred.get("startDateTime"))

                    # Expired secret
                    if end_dt and end_dt < now:
                        findings.append(ConnectorFinding(
                            title=f"App registration '{name}' has an expired client secret",
                            description=(
                                f"App registration '{name}' (appId: {app.get('appId')}) has a client "
                                f"secret that expired on {end_dt.date()}. Expired credentials may "
                                "cause authentication failures and indicate poor lifecycle management."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            resource_id=app.get("id", ""),
                            resource_type="Microsoft.AzureAD/applications",
                            control_id="NIST IA-5",
                            framework="nist_csf",
                            remediation=(
                                f"Remove the expired client secret from '{name}' and rotate "
                                "credentials. Consider migrating to certificate-based authentication."
                            ),
                        ))

                    # Long-lived secret (> 2 years)
                    if start_dt and end_dt:
                        lifetime_days = (end_dt - start_dt).days
                        if lifetime_days > 730:  # 2 years
                            findings.append(ConnectorFinding(
                                title=f"App registration '{name}' has a long-lived client secret (>2 years) — use certificate auth",
                                description=(
                                    f"App registration '{name}' has a client secret with a lifetime of "
                                    f"{lifetime_days} days (~{lifetime_days // 365} years). Long-lived "
                                    "secrets increase the window of exposure if the credential is "
                                    "leaked."
                                ),
                                severity=FindingSeverity.MEDIUM,
                                resource_id=app.get("id", ""),
                                resource_type="Microsoft.AzureAD/applications",
                                control_id="NIST IA-5",
                                framework="nist_csf",
                                remediation=(
                                    f"Replace the long-lived client secret on '{name}' with a "
                                    "certificate credential. Set maximum secret lifetime to 1 year "
                                    "via Entra ID app management policies."
                                ),
                            ))

                # Password creds without any certificate
                if password_creds and not key_creds:
                    findings.append(ConnectorFinding(
                        title=f"App registration '{name}' uses password credentials — prefer certificate-based auth",
                        description=(
                            f"App registration '{name}' authenticates using client secrets (passwords) "
                            "and has no certificate credentials configured. Client secrets are less "
                            "secure than certificates and are more frequently leaked."
                        ),
                        severity=FindingSeverity.LOW,
                        resource_id=app.get("id", ""),
                        resource_type="Microsoft.AzureAD/applications",
                        control_id="NIST IA-5",
                        framework="nist_csf",
                        remediation=(
                            f"Add a certificate credential to '{name}' and remove the client secret. "
                            "Use Managed Identity where possible to eliminate credential management "
                            "entirely."
                        ),
                    ))
        except Exception:
            pass
        return findings

    async def _check_password_policy(self) -> List[ConnectorFinding]:
        """
        Check tenant-level authorization policy for overly permissive user permissions.
        NIST IA-5 (password/auth strength) | NIST AC-6 (user permissions)
        resource_type: Microsoft.AzureAD/policies
        """
        findings: List[ConnectorFinding] = []
        try:
            authz_data = await self._graph_get("/policies/authorizationPolicy")
            # Response may be a single object or a list
            if isinstance(authz_data, list):
                policies = authz_data
            else:
                # Single-object response (most tenants)
                policies = authz_data.get("value", [authz_data])

            for policy in policies:
                default_perms = policy.get("defaultUserRolePermissions", {})

                if default_perms.get("allowedToCreateApps", False):
                    findings.append(ConnectorFinding(
                        title="All users can register applications — restrict to admins only",
                        description=(
                            "The tenant authorization policy allows all users to register Entra ID "
                            "application registrations. This can be abused to create malicious OAuth "
                            "apps or to bypass access controls."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        resource_type="Microsoft.AzureAD/policies",
                        control_id="NIST IA-5",
                        framework="nist_csf",
                        remediation=(
                            "In Entra ID > User Settings, set 'Users can register applications' to "
                            "No. Delegate app registration to a dedicated App Registrations role."
                        ),
                    ))

                if default_perms.get("allowedToCreateTenants", False):
                    findings.append(ConnectorFinding(
                        title="All users can create new Entra ID tenants",
                        description=(
                            "The tenant authorization policy permits all users to create new Entra ID "
                            "tenants. This can lead to shadow IT tenants outside corporate governance "
                            "and data exfiltration risk."
                        ),
                        severity=FindingSeverity.HIGH,
                        resource_type="Microsoft.AzureAD/policies",
                        control_id="NIST AC-6",
                        framework="nist_csf",
                        remediation=(
                            "In Entra ID > User Settings, set 'Restrict non-admin users from creating "
                            "tenants' to Yes (or configure via the authorizationPolicy API). Only "
                            "Global Administrators should be able to create tenants."
                        ),
                    ))
        except Exception:
            pass

        # Also check authentication strength policies (informational — no direct finding, but
        # absence of custom strength policies is noted if no CA MFA check already raised a CRITICAL)
        try:
            await self._graph_get("/policies/authenticationStrengthPolicies")
            # If the call succeeds, the tenant has defined auth strength policies — good hygiene.
            # We do not raise a finding here; the MFA CA check covers the enforcement gap.
        except Exception:
            pass

        return findings

    # ------------------------------------------------------------------
    # Remaining abstract implementations
    # ------------------------------------------------------------------

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []  # Identity posture is covered in config review

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
