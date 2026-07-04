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
        resources = []

        # Users with security-relevant properties
        try:
            users_data = await self._graph_get(
                "/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,signInActivity,assignedLicenses&$top=200"
            )
            for u in (users_data.get("value") or []):
                si = u.get("signInActivity") or {}
                resources.append({
                    "id": u.get("id", ""),
                    "name": u.get("displayName") or u.get("userPrincipalName", ""),
                    "type": "Microsoft.AzureAD/User",
                    "location": "",
                    "config": {
                        "user_type": u.get("userType"),
                        "account_enabled": u.get("accountEnabled"),
                        "last_sign_in": si.get("lastSignInDateTime"),
                        "has_licenses": bool(u.get("assignedLicenses")),
                    },
                })
        except Exception as exc:
            import logging as _lg
            _lg.getLogger(__name__).debug("EntraID get_resources users failed: %s", exc)

        # Applications with security-relevant credential info
        try:
            apps_data = await self._graph_get(
                "/applications?$select=id,displayName,appId,passwordCredentials,keyCredentials,verifiedPublisher&$top=100"
            )
            for a in (apps_data.get("value") or []):
                pw_creds = a.get("passwordCredentials") or []
                has_nonexpiring = any(not c.get("endDateTime") for c in pw_creds)
                resources.append({
                    "id": a.get("id", ""),
                    "name": a.get("displayName", ""),
                    "type": "Microsoft.AzureAD/Application",
                    "location": "",
                    "config": {
                        "app_id": a.get("appId"),
                        "secret_count": len(pw_creds),
                        "cert_count": len(a.get("keyCredentials") or []),
                        "has_nonexpiring_secret": has_nonexpiring,
                        "verified_publisher": bool(a.get("verifiedPublisher")),
                    },
                })
        except Exception as exc:
            import logging as _lg
            _lg.getLogger(__name__).debug("EntraID get_resources apps failed: %s", exc)

        # Conditional Access policies
        try:
            policies_data = await self._graph_get(
                "/identity/conditionalAccess/policies?$select=id,displayName,state,conditions,grantControls"
            )
            for p in (policies_data.get("value") or []):
                grant = p.get("grantControls") or {}
                built_in = grant.get("builtInControls") or []
                conditions = p.get("conditions") or {}
                resources.append({
                    "id": p.get("id", ""),
                    "name": p.get("displayName", ""),
                    "type": "Microsoft.AzureAD/ConditionalAccessPolicy",
                    "location": "",
                    "config": {
                        "state": p.get("state"),
                        "requires_mfa": "mfa" in built_in,
                        "blocks_legacy_auth": bool(
                            "exchangeActiveSync" in (conditions.get("clientAppTypes") or []) and
                            "block" in built_in
                        ),
                    },
                })
        except Exception as exc:
            import logging as _lg
            _lg.getLogger(__name__).debug("EntraID get_resources CA policies failed: %s", exc)

        return resources[:200]

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

        # --- Next-layer identity security checks ---
        findings.extend(await self._check_legacy_authentication())
        findings.extend(await self._check_identity_protection_risky_users())
        findings.extend(await self._check_identity_protection_risky_signins())
        findings.extend(await self._check_break_glass_accounts())
        findings.extend(await self._check_admin_consent_policy())
        findings.extend(await self._check_enterprise_applications())
        findings.extend(await self._check_authentication_methods_policy())
        findings.extend(await self._check_app_registration_owners())
        findings.extend(await self._check_sign_in_anomalies())

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

    async def _check_legacy_authentication(self) -> List[ConnectorFinding]:
        """
        Verify a Conditional Access policy exists that explicitly blocks legacy auth protocols.
        NIST IA-2 | resource_type: Microsoft.AzureAD/policies
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get("/identity/conditionalAccess/policies")
            policies = data.get("value", [])

            def _blocks_legacy_auth(policy: Dict) -> bool:
                if policy.get("state") != "enabled":
                    return False
                client_app_types = policy.get("conditions", {}).get("clientAppTypes", [])
                has_eas = "exchangeActiveSync" in client_app_types
                has_other = "other" in client_app_types
                grant = policy.get("grantControls") or {}
                operator_or = grant.get("operator") == "OR"
                built_in = grant.get("builtInControls", [])
                has_block = "block" in built_in
                return has_eas and has_other and operator_or and has_block

            if not any(_blocks_legacy_auth(p) for p in policies):
                findings.append(ConnectorFinding(
                    title="No Conditional Access policy blocking legacy authentication protocols",
                    description=(
                        "Legacy authentication protocols (SMTP AUTH, POP3, IMAP, MAPI, EWS, ActiveSync) "
                        "do not support modern MFA challenges. Attackers use these protocols to bypass "
                        "MFA entirely."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_type="Microsoft.AzureAD/policies",
                    control_id="NIST IA-2",
                    framework="nist_csf",
                    remediation=(
                        "Create a Conditional Access policy with condition 'Client apps = Exchange "
                        "ActiveSync clients + Other clients' and grant = Block."
                    ),
                ))
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("_check_legacy_authentication failed: %s", exc)
        return findings

    async def _check_identity_protection_risky_users(self) -> List[ConnectorFinding]:
        """
        Report users currently flagged as at-risk by Entra ID Identity Protection.
        Requires Entra ID P2 licence — handle 403 gracefully.
        NIST SI-4 | resource_type: Microsoft.AzureAD/riskyUsers
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get(
                "/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'&$top=50", beta=True
            )
            users = data.get("value", [])
            high_users = [u for u in users if u.get("riskLevel") == "high"]
            medium_users = [u for u in users if u.get("riskLevel") == "medium"]

            if high_users:
                findings.append(ConnectorFinding(
                    title=f"Entra ID Identity Protection: {len(high_users)} users flagged as HIGH risk",
                    description=(
                        "Identity Protection has detected anomalous behaviour for these users "
                        "(leaked credentials, impossible travel, anonymous IP, etc.). Their accounts "
                        "may be compromised."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    resource_type="Microsoft.AzureAD/riskyUsers",
                    control_id="NIST SI-4",
                    framework="nist_csf",
                    remediation=(
                        "Review each user in Entra ID → Identity Protection → Risky Users. "
                        "Confirm the risk is genuine, then require password reset + MFA "
                        "re-registration, or dismiss if false positive."
                    ),
                ))
            if medium_users:
                findings.append(ConnectorFinding(
                    title=f"Entra ID Identity Protection: {len(medium_users)} users flagged as MEDIUM risk",
                    description=(
                        "Identity Protection has detected anomalous behaviour for these users "
                        "(leaked credentials, impossible travel, anonymous IP, etc.). Their accounts "
                        "may be compromised."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_type="Microsoft.AzureAD/riskyUsers",
                    control_id="NIST SI-4",
                    framework="nist_csf",
                    remediation=(
                        "Review each user in Entra ID → Identity Protection → Risky Users. "
                        "Confirm the risk is genuine, then require password reset + MFA "
                        "re-registration, or dismiss if false positive."
                    ),
                ))
        except httpx.HTTPStatusError as exc:
            import logging
            logger = logging.getLogger(__name__)
            if exc.response.status_code == 403:
                logger.info(
                    "_check_identity_protection_risky_users: 403 Forbidden — "
                    "Entra ID Identity Protection requires a P2 licence."
                )
            else:
                logger.warning("_check_identity_protection_risky_users failed: %s", exc)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("_check_identity_protection_risky_users failed: %s", exc)
        return findings

    async def _check_identity_protection_risky_signins(self) -> List[ConnectorFinding]:
        """
        Report sign-in risk detections flagged by Entra ID Identity Protection.
        Requires Entra ID P2 licence — handle 403 gracefully.
        NIST AU-6 | resource_type: Microsoft.AzureAD/riskDetections
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get(
                "/identityProtection/riskDetections?$filter=riskState eq 'atRisk'&$top=100", beta=True
            )
            detections = data.get("value", [])
            high_count = sum(1 for d in detections if d.get("riskLevel") == "high")
            medium_count = sum(1 for d in detections if d.get("riskLevel") == "medium")

            # Top 3 deduplicated detection types for description enrichment
            event_types: List[str] = []
            seen: set = set()
            for d in detections:
                et = d.get("riskEventType", "")
                if et and et not in seen:
                    seen.add(et)
                    event_types.append(et)
                    if len(event_types) == 3:
                        break
            top_types_str = ", ".join(event_types) if event_types else "various"

            if high_count > 0:
                findings.append(ConnectorFinding(
                    title=f"Entra ID Identity Protection: {high_count} HIGH-risk sign-in detections in the current period",
                    description=(
                        f"Identity Protection has flagged {high_count} high-risk sign-in events "
                        f"(top detection types: {top_types_str}). These events may indicate active "
                        "account compromise."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    resource_type="Microsoft.AzureAD/riskDetections",
                    control_id="NIST AU-6",
                    framework="nist_csf",
                    remediation=(
                        "Review in Entra ID → Identity Protection → Risk Detections. Enable "
                        "risk-based Conditional Access policies to auto-remediate high-risk sign-ins."
                    ),
                ))
            if medium_count > 10:
                findings.append(ConnectorFinding(
                    title=f"Entra ID Identity Protection: {medium_count} MEDIUM-risk sign-in detections",
                    description=(
                        f"Identity Protection has flagged {medium_count} medium-risk sign-in events "
                        f"(top detection types: {top_types_str}). Elevated medium-risk volumes may "
                        "indicate broad credential attacks."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_type="Microsoft.AzureAD/riskDetections",
                    control_id="NIST AU-6",
                    framework="nist_csf",
                    remediation=(
                        "Review in Entra ID → Identity Protection → Risk Detections. Enable "
                        "risk-based Conditional Access policies to auto-remediate high-risk sign-ins."
                    ),
                ))
        except httpx.HTTPStatusError as exc:
            import logging
            logger = logging.getLogger(__name__)
            if exc.response.status_code == 403:
                logger.info(
                    "_check_identity_protection_risky_signins: 403 Forbidden — "
                    "Entra ID Identity Protection requires a P2 licence."
                )
            else:
                logger.warning("_check_identity_protection_risky_signins failed: %s", exc)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("_check_identity_protection_risky_signins failed: %s", exc)
        return findings

    async def _check_break_glass_accounts(self) -> List[ConnectorFinding]:
        """
        Detect presence of break-glass emergency accounts and verify CA policy exclusions.
        NIST CP-2 | resource_type: Microsoft.AzureAD/users
        """
        findings: List[ConnectorFinding] = []
        try:
            _BREAK_GLASS_KEYWORDS = {"break", "glass", "emergency", "bgaccount", "emergency-admin", "breakglass"}

            users_data = await self._graph_get(
                "/users?$filter=userType eq 'Member'"
                "&$select=displayName,userPrincipalName,accountEnabled,createdDateTime,id"
            )
            all_users = users_data.get("value", [])

            def _is_break_glass(user: Dict) -> bool:
                name = (user.get("displayName") or "").lower()
                upn = (user.get("userPrincipalName") or "").lower()
                return any(kw in name or kw in upn for kw in _BREAK_GLASS_KEYWORDS)

            bg_accounts = [u for u in all_users if _is_break_glass(u)]

            if not bg_accounts:
                findings.append(ConnectorFinding(
                    title="No break-glass (emergency access) accounts identified in the directory",
                    description=(
                        "Break-glass accounts are excluded from Conditional Access policies "
                        "(including MFA) and are used to recover tenant access if all regular admin "
                        "accounts are locked out. Their absence is a risk."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    resource_type="Microsoft.AzureAD/users",
                    control_id="NIST CP-2",
                    framework="nist_csf",
                    remediation=(
                        "Create 2 break-glass accounts with cloud-only credentials, exclude them "
                        "from all CA policies, store credentials in a physical safe, and monitor "
                        "them via alert rules."
                    ),
                ))
            else:
                # Check whether these accounts are excluded from all CA policies
                try:
                    ca_data = await self._graph_get("/identity/conditionalAccess/policies")
                    policies = ca_data.get("value", [])
                    bg_ids = {u.get("id") for u in bg_accounts if u.get("id")}

                    def _excluded_from_policy(policy: Dict, account_ids: set) -> bool:
                        exclude_users = (
                            policy.get("conditions", {})
                            .get("users", {})
                            .get("excludeUsers", [])
                        )
                        return bool(account_ids.intersection(set(exclude_users)))

                    all_excluded = all(
                        any(_excluded_from_policy(p, {uid}) for p in policies)
                        for uid in bg_ids
                    )

                    if not all_excluded:
                        findings.append(ConnectorFinding(
                            title="Break-glass accounts may not be excluded from all Conditional Access policies",
                            description=(
                                f"{len(bg_accounts)} break-glass account(s) were found but one or more "
                                "may not be excluded from all Conditional Access policies. If a CA "
                                "policy locks them out, tenant recovery may be impossible."
                            ),
                            severity=FindingSeverity.LOW,
                            resource_type="Microsoft.AzureAD/users",
                            control_id="NIST CP-2",
                            framework="nist_csf",
                            remediation=(
                                "Verify each break-glass account is explicitly excluded from every "
                                "Conditional Access policy via Entra ID → Conditional Access → "
                                "Exclusions."
                            ),
                        ))
                except Exception:
                    pass  # CA policy lookup is best-effort
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("_check_break_glass_accounts failed: %s", exc)
        return findings

    async def _check_admin_consent_policy(self) -> List[ConnectorFinding]:
        """
        Detect overly permissive OAuth consent settings that enable consent phishing.
        NIST AC-3 | resource_type: Microsoft.AzureAD/policies
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get("/policies/authorizationPolicy")
            policies = data.get("value", [data]) if isinstance(data, dict) and "value" not in data else data.get("value", [data])

            for policy in policies:
                # Check allowUserConsentForRiskyApps
                if policy.get("allowUserConsentForRiskyApps"):
                    findings.append(ConnectorFinding(
                        title="Users can consent to risky OAuth applications",
                        description=(
                            "This allows any user to consent to third-party OAuth applications "
                            "requesting access to their mailbox, files, and Teams data — a common "
                            "vector for business email compromise via OAuth phishing (consent phishing)."
                        ),
                        severity=FindingSeverity.HIGH,
                        resource_type="Microsoft.AzureAD/policies",
                        control_id="NIST AC-3",
                        framework="nist_csf",
                        remediation=(
                            "Set user consent to 'Allow user consent for apps from verified "
                            "publishers' or 'Require admin approval for all apps' in Entra ID → "
                            "Enterprise Applications → Consent and Permissions."
                        ),
                    ))

                # Check for legacy consent policy
                grant_policy_ids = policy.get("permissionGrantPolicyIdsAssignedToDefaultUserRole", []) or []
                if "ManagePermissionGrantsForSelf.microsoft-user-default-legacy-policy" in grant_policy_ids:
                    findings.append(ConnectorFinding(
                        title="Users can grant OAuth app consent without admin approval (legacy policy)",
                        description=(
                            "This allows any user to consent to third-party OAuth applications "
                            "requesting access to their mailbox, files, and Teams data — a common "
                            "vector for business email compromise via OAuth phishing (consent phishing)."
                        ),
                        severity=FindingSeverity.HIGH,
                        resource_type="Microsoft.AzureAD/policies",
                        control_id="NIST AC-3",
                        framework="nist_csf",
                        remediation=(
                            "Set user consent to 'Allow user consent for apps from verified "
                            "publishers' or 'Require admin approval for all apps' in Entra ID → "
                            "Enterprise Applications → Consent and Permissions."
                        ),
                    ))
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("_check_admin_consent_policy failed: %s", exc)
        return findings

    async def _check_enterprise_applications(self) -> List[ConnectorFinding]:
        """
        Audit enterprise applications (service principals) for non-expiring secrets,
        unverified publishers with high privileges, and missing publisher info.
        NIST AC-3 | resource_type: Microsoft.AzureAD/servicePrincipals
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get(
                "/servicePrincipals"
                "?$select=displayName,appId,publisherName,verifiedPublisher,"
                "oauth2PermissionScopes,keyCredentials,passwordCredentials"
                "&$top=200"
            )
            apps = data.get("value", [])
            seen_app_ids: set = set()

            _HIGH_PRIV_SCOPES = {"Directory.Read.All", "Mail.Read", "Files.ReadWrite.All"}

            for app in apps:
                app_id = app.get("appId", "")
                if app_id in seen_app_ids:
                    continue
                seen_app_ids.add(app_id)

                name = app.get("displayName") or app_id or "unknown"
                password_creds = app.get("passwordCredentials") or []
                key_creds = app.get("keyCredentials") or []
                verified_publisher = app.get("verifiedPublisher") or {}
                publisher_name = app.get("publisherName")
                oauth_scopes = [
                    s.get("value", "") for s in (app.get("oauth2PermissionScopes") or [])
                ]

                # Non-expiring client secrets
                for cred in password_creds:
                    if not cred.get("endDateTime"):
                        findings.append(ConnectorFinding(
                            title=f"Enterprise app '{name}' has a non-expiring client secret",
                            description=(
                                f"Enterprise application '{name}' has a client secret with no "
                                "expiry date. Non-expiring secrets remain valid indefinitely and "
                                "increase the blast radius of a credential leak."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            resource_type="Microsoft.AzureAD/servicePrincipals",
                            control_id="NIST AC-3",
                            framework="nist_csf",
                            remediation=(
                                f"Set an expiry date on all client secrets for '{name}' and rotate "
                                "them on a regular schedule (maximum 1 year)."
                            ),
                        ))
                        break  # One finding per app for this issue

                # Unverified publisher with high-privilege scopes
                is_verified = bool(verified_publisher.get("displayName"))
                has_high_priv = bool(_HIGH_PRIV_SCOPES.intersection(set(oauth_scopes)))
                if not is_verified and has_high_priv:
                    findings.append(ConnectorFinding(
                        title=f"Unverified enterprise app '{name}' has high-privilege directory permissions",
                        description=(
                            f"Enterprise application '{name}' has been granted high-privilege "
                            "permissions (Directory.Read.All, Mail.Read, or Files.ReadWrite.All) "
                            "but its publisher is not verified by Microsoft."
                        ),
                        severity=FindingSeverity.HIGH,
                        resource_type="Microsoft.AzureAD/servicePrincipals",
                        control_id="NIST AC-3",
                        framework="nist_csf",
                        remediation=(
                            f"Review whether '{name}' still requires these permissions. If the app "
                            "is internal, complete Microsoft publisher verification. If external, "
                            "confirm it is legitimate before retaining these grants."
                        ),
                    ))

                # No verified publisher but has any credentials
                has_creds = bool(password_creds or key_creds)
                if not publisher_name and has_creds:
                    findings.append(ConnectorFinding(
                        title=f"Enterprise app '{name}' has no verified publisher — treat as untrusted",
                        description=(
                            f"Enterprise application '{name}' has credentials configured but no "
                            "verified publisher name. Apps without a verified publisher identity "
                            "are harder to audit and may be shadow IT or malicious."
                        ),
                        severity=FindingSeverity.LOW,
                        resource_type="Microsoft.AzureAD/servicePrincipals",
                        control_id="NIST AC-3",
                        framework="nist_csf",
                        remediation=(
                            f"Identify the owner of '{name}', confirm its purpose, and either "
                            "complete publisher verification or remove the application."
                        ),
                    ))
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("_check_enterprise_applications failed: %s", exc)
        return findings

    async def _check_authentication_methods_policy(self) -> List[ConnectorFinding]:
        """
        Review enabled authentication methods for phishable-only configurations and
        absence of phishing-resistant alternatives.
        NIST IA-2 | resource_type: Microsoft.AzureAD/policies
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get("/policies/authenticationMethodsPolicy")
            configs = data.get("authenticationMethodConfigurations") or []

            method_states: Dict[str, str] = {}
            method_details: Dict[str, Dict] = {}
            for cfg in configs:
                method_id = cfg.get("id", "")
                method_states[method_id] = cfg.get("state", "disabled")
                method_details[method_id] = cfg

            authenticator_enabled = method_states.get("MicrosoftAuthenticator") == "enabled"
            sms_enabled = method_states.get("Sms") == "enabled"
            voice_enabled = method_states.get("Voice") == "enabled"
            fido2_enabled = method_states.get("Fido2") == "enabled"

            # Phishable-only: SMS or voice enabled but Authenticator disabled
            if (sms_enabled or voice_enabled) and not authenticator_enabled:
                findings.append(ConnectorFinding(
                    title="Phishable authentication methods (SMS/voice) are enabled without phishing-resistant alternatives",
                    description=(
                        "SMS and voice call OTP authentication can be intercepted via SIM-swapping "
                        "or SS7 attacks. Without Microsoft Authenticator or FIDO2 as alternatives, "
                        "all MFA in the tenant is phishable."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    resource_type="Microsoft.AzureAD/policies",
                    control_id="NIST IA-2",
                    framework="nist_csf",
                    remediation=(
                        "Enable Microsoft Authenticator push notifications or FIDO2 security keys "
                        "in Entra ID → Authentication Methods → Policies, and encourage users to "
                        "register phishing-resistant credentials."
                    ),
                ))

            # Authenticator enabled with TOTP but no FIDO2
            authenticator_cfg = method_details.get("MicrosoftAuthenticator", {})
            soft_oath_enabled = authenticator_cfg.get("isSoftwareOathEnabled", False)
            if authenticator_enabled and soft_oath_enabled and not fido2_enabled:
                findings.append(ConnectorFinding(
                    title="FIDO2/passkey authentication is not enabled — consider adding phishing-resistant auth",
                    description=(
                        "Microsoft Authenticator TOTP codes are enabled but FIDO2 security keys "
                        "(passkeys) are not. FIDO2 provides the highest phishing resistance and "
                        "meets AAL3 requirements."
                    ),
                    severity=FindingSeverity.LOW,
                    resource_type="Microsoft.AzureAD/policies",
                    control_id="NIST IA-2",
                    framework="nist_csf",
                    remediation=(
                        "Enable FIDO2 security keys in Entra ID → Authentication Methods → "
                        "FIDO2 Security Key. Consider deploying hardware keys to privileged users."
                    ),
                ))

            # Microsoft Authenticator disabled entirely
            if not authenticator_enabled:
                findings.append(ConnectorFinding(
                    title="Microsoft Authenticator app push notifications are disabled — consider enabling for MFA",
                    description=(
                        "The Microsoft Authenticator authentication method is disabled for this "
                        "tenant. Authenticator push notifications are the most user-friendly "
                        "phishing-resistant MFA method available without hardware tokens."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_type="Microsoft.AzureAD/policies",
                    control_id="NIST IA-2",
                    framework="nist_csf",
                    remediation=(
                        "Enable Microsoft Authenticator in Entra ID → Authentication Methods → "
                        "Microsoft Authenticator and target all users or privileged users first."
                    ),
                ))
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("_check_authentication_methods_policy failed: %s", exc)
        return findings

    async def _check_app_registration_owners(self) -> List[ConnectorFinding]:
        """
        Identify app registrations with no owners or with external guest owners.
        NIST AC-2 | resource_type: Microsoft.AzureAD/applications
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get("/applications?$select=displayName,appId,id&$top=100")
            apps = data.get("value", [])

            for app in apps:
                app_obj_id = app.get("id", "")
                name = app.get("displayName") or app.get("appId", "unknown")

                try:
                    owners_data = await self._graph_get(f"/applications/{app_obj_id}/owners")
                    owners = owners_data.get("value", [])
                except Exception:
                    continue  # Cannot read owners — skip this app

                if not owners:
                    findings.append(ConnectorFinding(
                        title=f"App registration '{name}' has no owners assigned",
                        description=(
                            f"App registration '{name}' (id: {app_obj_id}) has no owners. "
                            "Ownerless app registrations cannot be managed, rotated, or "
                            "decommissioned by an accountable individual. This is an orphaned "
                            "credential risk."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        resource_id=app_obj_id,
                        resource_type="Microsoft.AzureAD/applications",
                        control_id="NIST AC-2",
                        framework="nist_csf",
                        remediation=(
                            f"Assign at least one owner to each app registration via Entra ID → "
                            f"App registrations → {name} → Owners."
                        ),
                    ))
                else:
                    for owner in owners:
                        user_type = owner.get("userType", "")
                        guest_email = (
                            owner.get("mail")
                            or owner.get("userPrincipalName")
                            or owner.get("id", "unknown")
                        )
                        if user_type == "Guest":
                            findings.append(ConnectorFinding(
                                title=f"External guest user '{guest_email}' is an owner of app registration '{name}'",
                                description=(
                                    f"External guest user '{guest_email}' is listed as an owner of "
                                    f"app registration '{name}'. Guests can modify the application's "
                                    "credentials and redirect URIs, which could enable account takeover."
                                ),
                                severity=FindingSeverity.HIGH,
                                resource_id=app_obj_id,
                                resource_type="Microsoft.AzureAD/applications",
                                control_id="NIST AC-2",
                                framework="nist_csf",
                                remediation=(
                                    f"Remove guest user '{guest_email}' as an owner of '{name}'. "
                                    "App registration owners should be internal members only."
                                ),
                            ))
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("_check_app_registration_owners failed: %s", exc)
        return findings

    async def _check_sign_in_anomalies(self) -> List[ConnectorFinding]:
        """
        Detect potential credential-stuffing by counting distinct countries with
        failed sign-ins in the most recent 100 log entries.
        Requires AuditLog.Read.All — handle 403 gracefully.
        NIST SI-4 | resource_type: Microsoft.AzureAD/signIns
        """
        findings: List[ConnectorFinding] = []
        try:
            data = await self._graph_get(
                "/auditLogs/signIns"
                "?$filter=status/errorCode ne 0"
                "&$top=100"
                "&$orderby=createdDateTime desc"
            )
            sign_ins = data.get("value", [])

            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(hours=24)

            countries: set = set()
            for si in sign_ins:
                created_str = si.get("createdDateTime")
                created = self._parse_dt(created_str)
                if created and created < cutoff:
                    continue  # Outside 24-hour window
                country = (si.get("location") or {}).get("countryOrRegion")
                if country:
                    countries.add(country)

            if len(countries) > 3:
                findings.append(ConnectorFinding(
                    title=(
                        f"Sign-in anomaly: failed logins detected from {len(countries)} countries "
                        "in the past 24 hours — possible credential stuffing"
                    ),
                    description=(
                        "Multiple failed authentication attempts from geographically dispersed "
                        "locations suggest an automated credential stuffing or password spray "
                        f"attack is underway. Countries observed: {', '.join(sorted(countries))}."
                    ),
                    severity=FindingSeverity.HIGH,
                    resource_type="Microsoft.AzureAD/signIns",
                    control_id="NIST SI-4",
                    framework="nist_csf",
                    remediation=(
                        "Review sign-in logs in Entra ID. Enable Entra ID Identity Protection and "
                        "configure risk-based CA policies to block or challenge risky sign-ins."
                    ),
                ))
        except httpx.HTTPStatusError as exc:
            import logging
            logger = logging.getLogger(__name__)
            if exc.response.status_code == 403:
                logger.info(
                    "_check_sign_in_anomalies: 403 Forbidden — AuditLog.Read.All permission required."
                )
            else:
                logger.warning("_check_sign_in_anomalies failed: %s", exc)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("_check_sign_in_anomalies failed: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Remaining abstract implementations
    # ------------------------------------------------------------------

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []  # Identity posture is covered in config review

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
