"""
NexGenCyberAI - Entra ID (Azure AD) Connector
Reads identity posture: MFA status, risky users, risky sign-ins,
conditional access policies, privileged accounts.
Uses Microsoft Graph API via MSAL client credentials.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List
import httpx
import msal
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

logger = logging.getLogger(__name__)


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
        """Collect all identity security-relevant assets from Entra ID.

        Each resource is stored as an Asset + AssetPlatformDetail so the
        config-compliance engine can evaluate controls from real data rather
        than just from findings.

        Permissions required at minimum (app registration):
          User.Read.All, Application.Read.All, Policy.Read.All, Directory.Read.All
        Optional (degrade gracefully when absent):
          AuditLog.Read.All          → signInActivity, sign-in logs
          Reports.Read.All            → MFA registration report
          IdentityRiskyUser.Read.All  → Identity Protection risk levels (P2)
        """
        resources = []

        # ── 1. Users ─────────────────────────────────────────────────────────
        # Base call uses only User.Read.All — always succeeds.
        # signInActivity needs AuditLog.Read.All; fetch separately so a missing
        # permission doesn't wipe out all user assets.
        try:
            # Optional: MFA registration (Reports.Read.All)
            mfa_map: Dict[str, bool] = {}
            try:
                mfa_data = await self._graph_get(
                    "/reports/authenticationMethods/userRegistrationDetails"
                    "?$select=id,isMfaRegistered,isMfaCapable,isPasswordlessCapable"
                    "&$top=500",
                    beta=True,
                )
                for row in mfa_data.get("value") or []:
                    mfa_map[row["id"]] = bool(row.get("isMfaRegistered"))
            except Exception:
                pass  # Needs Reports.Read.All — degrade gracefully

            # Optional: risk levels (IdentityRiskyUser.Read.All + P2)
            risk_map: Dict[str, str] = {}
            try:
                risk_data = await self._graph_get(
                    "/identityProtection/riskyUsers?$select=id,riskLevel,riskState&$top=500",
                    beta=True,
                )
                for row in risk_data.get("value") or []:
                    risk_map[row["id"]] = row.get("riskLevel", "none")
            except Exception:
                pass  # Needs IdentityRiskyUser.Read.All — degrade gracefully

            # Optional: sign-in activity (AuditLog.Read.All)
            signin_map: Dict[str, str] = {}
            try:
                si_data = await self._graph_get(
                    "/users?$select=id,signInActivity&$top=500"
                )
                for row in si_data.get("value") or []:
                    si = row.get("signInActivity") or {}
                    signin_map[row["id"]] = si.get("lastSignInDateTime")
            except Exception:
                pass  # Needs AuditLog.Read.All — degrade gracefully

            # Base user list — only fields guaranteed by User.Read.All
            users_data = await self._graph_get(
                "/users"
                "?$select=id,displayName,userPrincipalName,userType,accountEnabled"
                ",assignedLicenses,createdDateTime,mail,onPremisesSyncEnabled"
                "&$top=500"
            )
            for u in (users_data.get("value") or []):
                uid = u.get("id", "")
                resources.append({
                    "id": uid,
                    "name": u.get("displayName") or u.get("userPrincipalName", ""),
                    "type": "Microsoft.AzureAD/User",
                    "location": "",
                    "config": {
                        "user_type": u.get("userType"),             # Member | Guest
                        "account_enabled": u.get("accountEnabled"),
                        "last_sign_in": signin_map.get(uid),        # None if AuditLog.Read.All absent
                        "has_licenses": bool(u.get("assignedLicenses")),
                        "is_mfa_registered": mfa_map.get(uid),      # None if Reports.Read.All absent
                        "risk_level": risk_map.get(uid, "none"),     # none/low/medium/high
                        "on_premises_sync": u.get("onPremisesSyncEnabled"),
                        "created_at": u.get("createdDateTime"),
                        "mail": u.get("mail"),
                    },
                })
        except Exception as exc:
            logger.warning("EntraID get_resources users failed: %s", exc)

        # ── 2. Applications (app registrations) ──────────────────────────────
        try:
            now_dt = datetime.now(timezone.utc)
            apps_data = await self._graph_get(
                "/applications"
                "?$select=id,displayName,appId,passwordCredentials,keyCredentials"
                ",verifiedPublisher,createdDateTime,signInAudience"
                "&$top=200"
            )
            for a in (apps_data.get("value") or []):
                pw_creds = a.get("passwordCredentials") or []
                key_creds = a.get("keyCredentials") or []
                has_nonexpiring = any(not c.get("endDateTime") for c in pw_creds)
                has_expired = any(
                    self._parse_dt(c.get("endDateTime")) and
                    self._parse_dt(c.get("endDateTime")) < now_dt
                    for c in pw_creds
                )
                longest_secret_days = max(
                    (
                        (self._parse_dt(c.get("endDateTime")) - self._parse_dt(c.get("startDateTime"))).days
                        for c in pw_creds
                        if self._parse_dt(c.get("endDateTime")) and self._parse_dt(c.get("startDateTime"))
                    ),
                    default=0,
                )
                resources.append({
                    "id": a.get("id", ""),
                    "name": a.get("displayName", ""),
                    "type": "Microsoft.AzureAD/Application",
                    "location": "",
                    "config": {
                        "app_id": a.get("appId"),
                        "sign_in_audience": a.get("signInAudience"),  # AzureADMyOrg | AzureADMultipleOrgs | AzureADandPersonalMicrosoftAccount
                        "secret_count": len(pw_creds),
                        "cert_count": len(key_creds),
                        "has_nonexpiring_secret": has_nonexpiring,
                        "has_expired_secret": has_expired,
                        "longest_secret_days": longest_secret_days,
                        "uses_cert_auth": len(key_creds) > 0,
                        "verified_publisher": bool(a.get("verifiedPublisher")),
                        "created_at": a.get("createdDateTime"),
                    },
                })
        except Exception as exc:
            logger.debug("EntraID get_resources apps failed: %s", exc)

        # ── 3. Conditional Access policies ───────────────────────────────────
        try:
            policies_data = await self._graph_get(
                "/identity/conditionalAccess/policies"
                "?$select=id,displayName,state,conditions,grantControls,sessionControls"
            )
            for p in (policies_data.get("value") or []):
                grant = p.get("grantControls") or {}
                built_in = grant.get("builtInControls") or []
                conditions = p.get("conditions") or {}
                users_cond = conditions.get("users") or {}
                client_app_types = conditions.get("clientAppTypes") or []
                resources.append({
                    "id": p.get("id", ""),
                    "name": p.get("displayName", ""),
                    "type": "Microsoft.AzureAD/ConditionalAccessPolicy",
                    "location": "",
                    "config": {
                        "state": p.get("state"),                     # enabled | disabled | enabledForReportingButNotEnforced
                        "requires_mfa": "mfa" in built_in,
                        "blocks_access": "block" in built_in,
                        "blocks_legacy_auth": (
                            "exchangeActiveSync" in client_app_types and
                            "other" in client_app_types and
                            "block" in built_in
                        ),
                        "targets_all_users": "All" in (users_cond.get("includeUsers") or []),
                        "exclude_users": users_cond.get("excludeUsers") or [],
                        "include_apps": (conditions.get("applications") or {}).get("includeApplications") or [],
                        "sign_in_frequency_enabled": bool(
                            (p.get("sessionControls") or {}).get("signInFrequency", {}).get("isEnabled")
                        ),
                    },
                })
        except Exception as exc:
            logger.debug("EntraID get_resources CA policies failed: %s", exc)

        # ── 4. Privileged directory roles (with member counts) ───────────────
        _PRIVILEGED = {
            "Global Administrator", "Privileged Role Administrator",
            "Security Administrator", "Exchange Administrator",
            "SharePoint Administrator", "Teams Administrator",
            "Application Administrator", "Cloud Application Administrator",
            "Helpdesk Administrator", "User Administrator",
        }
        try:
            roles_data = await self._graph_get("/directoryRoles")
            for role in (roles_data.get("value") or []):
                role_name = role.get("displayName", "")
                role_id = role.get("id", "")
                members: List[Dict] = []
                try:
                    mem_data = await self._graph_get(f"/directoryRoles/{role_id}/members?$select=id,displayName,userPrincipalName,userType")
                    members = mem_data.get("value") or []
                except Exception:
                    pass
                guest_members = [m for m in members if m.get("userType") == "Guest"]
                resources.append({
                    "id": role_id,
                    "name": role_name,
                    "type": "Microsoft.AzureAD/DirectoryRole",
                    "location": "",
                    "config": {
                        "is_privileged": role_name in _PRIVILEGED,
                        "member_count": len(members),
                        "guest_member_count": len(guest_members),
                        "member_upns": [m.get("userPrincipalName") or m.get("displayName") for m in members[:20]],
                    },
                })
        except Exception as exc:
            logger.debug("EntraID get_resources directory roles failed: %s", exc)

        # ── 5. Authentication Methods Policy (tenant-level singleton) ────────
        try:
            amp = await self._graph_get("/policies/authenticationMethodsPolicy")
            configs = amp.get("authenticationMethodConfigurations") or []
            method_states = {c.get("id"): c.get("state") for c in configs}
            resources.append({
                "id": "authenticationMethodsPolicy",
                "name": "Authentication Methods Policy",
                "type": "Microsoft.AzureAD/AuthenticationMethodsPolicy",
                "location": "",
                "config": {
                    "authenticator_app_enabled": method_states.get("MicrosoftAuthenticator") == "enabled",
                    "fido2_enabled": method_states.get("Fido2") == "enabled",
                    "sms_enabled": method_states.get("Sms") == "enabled",
                    "voice_enabled": method_states.get("Voice") == "enabled",
                    "email_otp_enabled": method_states.get("Email") == "enabled",
                    "temp_access_pass_enabled": method_states.get("TemporaryAccessPass") == "enabled",
                    "software_oath_enabled": method_states.get("SoftwareOath") == "enabled",
                    "passkey_enabled": method_states.get("Passkey") == "enabled",
                    # True when phishable-only methods enabled and no strong method available
                    "phishable_only": (
                        (method_states.get("Sms") == "enabled" or method_states.get("Voice") == "enabled") and
                        method_states.get("MicrosoftAuthenticator") != "enabled" and
                        method_states.get("Fido2") != "enabled"
                    ),
                },
            })
        except Exception as exc:
            logger.debug("EntraID get_resources auth methods policy failed: %s", exc)

        # ── 6. Authorization Policy (user consent, app creation, tenant creation) ──
        try:
            authz = await self._graph_get("/policies/authorizationPolicy")
            # API returns either a single object or {value: [...]}
            if isinstance(authz, dict) and "value" in authz:
                authz = (authz["value"] or [{}])[0]
            default_perms = authz.get("defaultUserRolePermissions") or {}
            resources.append({
                "id": "authorizationPolicy",
                "name": "Authorization Policy",
                "type": "Microsoft.AzureAD/AuthorizationPolicy",
                "location": "",
                "config": {
                    "users_can_register_apps": default_perms.get("allowedToCreateApps", False),
                    "users_can_create_tenants": default_perms.get("allowedToCreateTenants", False),
                    "users_can_create_security_groups": default_perms.get("allowedToCreateSecurityGroups", False),
                    "users_can_read_other_users": default_perms.get("allowedToReadOtherUsers", True),
                    "guest_invite_settings": authz.get("allowInvitesFrom"),      # adminsAndGuestInviters | adminsAndGuestInvitersAndAllMembers | everyone | none
                    "guest_user_role": authz.get("guestUserRoleId"),             # specific GUID maps to Guest, Restricted Guest, or Member
                    "allow_user_consent_for_risky_apps": authz.get("allowUserConsentForRiskyApps", False),
                    "permission_grant_policies": authz.get("permissionGrantPolicyIdsAssignedToDefaultUserRole") or [],
                },
            })
        except Exception as exc:
            logger.debug("EntraID get_resources authorization policy failed: %s", exc)

        # ── 7. Named Locations (trusted IP ranges and countries) ─────────────
        try:
            named_locs = await self._graph_get("/identity/conditionalAccess/namedLocations")
            for loc in (named_locs.get("value") or []):
                odata_type = loc.get("@odata.type", "")
                resources.append({
                    "id": loc.get("id", ""),
                    "name": loc.get("displayName", ""),
                    "type": "Microsoft.AzureAD/NamedLocation",
                    "location": "",
                    "config": {
                        "location_type": "ip_range" if "ipNamed" in odata_type else "country",
                        "is_trusted": loc.get("isTrusted", False),
                        "ip_ranges": [r.get("cidrAddress") for r in (loc.get("ipRanges") or [])],
                        "countries": loc.get("countriesAndRegions") or [],
                        "include_unknown_countries": loc.get("includeUnknownCountriesAndRegions", False),
                    },
                })
        except Exception as exc:
            logger.debug("EntraID get_resources named locations failed: %s", exc)

        # ── 8. Password Reset Policy (SSPR) — beta, optional ────────────────
        try:
            sspr = await self._graph_get("/policies/selfServiceSignUpAuthenticationFlowConfiguration", beta=True)
            resources.append({
                "id": "passwordResetPolicy",
                "name": "Password Reset Policy (SSPR)",
                "type": "Microsoft.AzureAD/PasswordResetPolicy",
                "location": "",
                "config": {
                    "sspr_enabled": bool(sspr.get("isEnabled")),
                },
            })
        except Exception as exc:
            logger.debug("EntraID get_resources SSPR policy failed: %s", exc)

        # ── 9. External collaboration settings (v1.0) ─────────────────────
        try:
            authz = await self._graph_get("/policies/authorizationPolicy")
            authz_obj = authz if isinstance(authz, dict) and "allowInvitesFrom" in authz else {}
            if not authz_obj and isinstance(authz, dict):
                authz_obj = (authz.get("value") or [{}])[0]
            if authz_obj.get("allowInvitesFrom"):
                resources.append({
                    "id": "externalIdentitiesPolicy",
                    "name": "External Collaboration Settings",
                    "type": "Microsoft.AzureAD/ExternalIdentitiesPolicy",
                    "location": "",
                    "config": {
                        "allow_invitations_from": authz_obj.get("allowInvitesFrom"),
                    },
                })
        except Exception as exc:
            logger.debug("EntraID get_resources external identities policy failed: %s", exc)

        # ── 10. Service Principals (enterprise apps — first 200) ─────────────
        try:
            sp_data = await self._graph_get(
                "/servicePrincipals"
                "?$select=id,displayName,appId,publisherName,verifiedPublisher"
                ",passwordCredentials,keyCredentials,oauth2PermissionScopes,servicePrincipalType"
                "&$top=200"
            )
            _HIGH_PRIV = {"Directory.Read.All", "Mail.Read", "Files.ReadWrite.All",
                          "User.ReadWrite.All", "GroupMember.ReadWrite.All"}
            for sp in (sp_data.get("value") or []):
                pw_creds = sp.get("passwordCredentials") or []
                key_creds = sp.get("keyCredentials") or []
                scopes = {s.get("value", "") for s in (sp.get("oauth2PermissionScopes") or [])}
                resources.append({
                    "id": sp.get("id", ""),
                    "name": sp.get("displayName", ""),
                    "type": "Microsoft.AzureAD/ServicePrincipal",
                    "location": "",
                    "config": {
                        "app_id": sp.get("appId"),
                        "sp_type": sp.get("servicePrincipalType"),     # Application | ManagedIdentity | Legacy
                        "has_nonexpiring_secret": any(not c.get("endDateTime") for c in pw_creds),
                        "secret_count": len(pw_creds),
                        "cert_count": len(key_creds),
                        "verified_publisher": bool((sp.get("verifiedPublisher") or {}).get("displayName")),
                        "publisher_name": sp.get("publisherName"),
                        "has_high_priv_scopes": bool(_HIGH_PRIV.intersection(scopes)),
                        "high_priv_scopes": list(_HIGH_PRIV.intersection(scopes)),
                    },
                })
        except Exception as exc:
            logger.debug("EntraID get_resources service principals failed: %s", exc)

        # ── 11. Devices ───────────────────────────────────────────────────────
        # Requires Device.Read.All
        try:
            dev_data = await self._graph_get(
                "/devices"
                "?$select=id,displayName,operatingSystem,operatingSystemVersion"
                ",isCompliant,isManaged,trustType,registrationDateTime"
                ",approximateLastSignInDateTime,deviceId,profileType"
                "&$top=500"
            )
            for d in (dev_data.get("value") or []):
                resources.append({
                    "id": d.get("id", ""),
                    "name": d.get("displayName", ""),
                    "type": "Microsoft.AzureAD/Device",
                    "location": "",
                    "config": {
                        "os": d.get("operatingSystem"),
                        "os_version": d.get("operatingSystemVersion"),
                        "is_compliant": d.get("isCompliant"),           # None = no compliance policy
                        "is_managed": d.get("isManaged"),
                        "trust_type": d.get("trustType"),               # AzureAD | ServerAD | Workplace
                        "profile_type": d.get("profileType"),           # RegisteredDevice | SecureVM | Printer | Shared | IoT
                        "registered_at": d.get("registrationDateTime"),
                        "last_sign_in": d.get("approximateLastSignInDateTime"),
                        "device_id": d.get("deviceId"),
                    },
                })
        except Exception as exc:
            logger.debug("EntraID get_resources devices failed: %s", exc)

        # ── 12. Security Defaults ─────────────────────────────────────────────
        # Singleton — requires Policy.Read.All
        try:
            sd = await self._graph_get("/policies/identitySecurityDefaultsEnforcementPolicy")
            resources.append({
                "id": "identitySecurityDefaultsEnforcementPolicy",
                "name": "Security Defaults",
                "type": "Microsoft.AzureAD/SecurityDefaultsPolicy",
                "location": "",
                "config": {
                    "is_enabled": sd.get("isEnabled", False),
                },
            })
        except Exception as exc:
            logger.debug("EntraID get_resources security defaults failed: %s", exc)

        # ── 13. Device Registration Policy ───────────────────────────────────
        # Singleton — requires Policy.Read.All
        try:
            drp = await self._graph_get("/policies/deviceRegistrationPolicy", beta=True)
            local_admins = drp.get("localAdmins") or {}
            resources.append({
                "id": "deviceRegistrationPolicy",
                "name": "Device Registration Policy",
                "type": "Microsoft.AzureAD/DeviceRegistrationPolicy",
                "location": "",
                "config": {
                    "user_device_quota": drp.get("userDeviceQuota"),
                    "azure_ad_join_enabled": (drp.get("azureADJoin") or {}).get("isAdminConfigurable"),
                    "azure_ad_register_enabled": (drp.get("azureADRegistration") or {}).get("isAdminConfigurable"),
                    "local_admin_enabled": local_admins.get("enableGlobalAdmins"),
                    "local_admin_scope": (local_admins.get("registeringUsers") or {}).get("allowedToJoin"),
                },
            })
        except Exception as exc:
            logger.debug("EntraID get_resources device registration policy failed: %s", exc)

        # ── 14. Custom Domain Names ───────────────────────────────────────────
        # Requires Domain.Read.All
        try:
            domains_data = await self._graph_get(
                "/domains?$select=id,isDefault,isVerified,isAdminManaged"
                ",authenticationType,availabilityStatus,supportedServices"
            )
            for dom in (domains_data.get("value") or []):
                resources.append({
                    "id": dom.get("id", ""),         # domain name is the id (e.g. contoso.com)
                    "name": dom.get("id", ""),
                    "type": "Microsoft.AzureAD/Domain",
                    "location": "",
                    "config": {
                        "is_default": dom.get("isDefault"),
                        "is_verified": dom.get("isVerified"),
                        "is_admin_managed": dom.get("isAdminManaged"),
                        "authentication_type": dom.get("authenticationType"),  # Managed | Federated
                        "availability_status": dom.get("availabilityStatus"),
                        "supported_services": dom.get("supportedServices") or [],
                        "is_federated": dom.get("authenticationType") == "Federated",
                    },
                })
        except Exception as exc:
            logger.debug("EntraID get_resources domains failed: %s", exc)

        # ── 15. Risky Users (P2 — degrades gracefully) ───────────────────────
        # Requires IdentityRiskyUser.Read.All + Entra P2 licence
        try:
            ru_data = await self._graph_get(
                "/identityProtection/riskyUsers"
                "?$select=id,userPrincipalName,riskLevel,riskState,riskDetail,riskLastUpdatedDateTime"
                "&$top=500",
                beta=True,
            )
            for ru in (ru_data.get("value") or []):
                if ru.get("riskLevel") in ("none", None):
                    continue  # skip non-risky users — findings already cover them
                resources.append({
                    "id": ru.get("id", ""),
                    "name": ru.get("userPrincipalName") or ru.get("id", ""),
                    "type": "Microsoft.AzureAD/RiskyUser",
                    "location": "",
                    "config": {
                        "risk_level": ru.get("riskLevel"),      # low | medium | high
                        "risk_state": ru.get("riskState"),      # atRisk | confirmedCompromised | remediated | dismissed
                        "risk_detail": ru.get("riskDetail"),
                        "risk_last_updated": ru.get("riskLastUpdatedDateTime"),
                    },
                })
        except Exception:
            pass  # P2 licence required — degrade gracefully

        # ── 16. Risky Workload Identities (P2 — degrades gracefully) ─────────
        # Requires IdentityRiskyServicePrincipal.Read.All + Entra P2
        try:
            rwi_data = await self._graph_get(
                "/identityProtection/riskyServicePrincipals"
                "?$select=id,displayName,appId,riskLevel,riskState,riskDetail"
                "&$top=200",
                beta=True,
            )
            for rwi in (rwi_data.get("value") or []):
                if rwi.get("riskLevel") in ("none", None):
                    continue
                resources.append({
                    "id": rwi.get("id", ""),
                    "name": rwi.get("displayName") or rwi.get("appId", ""),
                    "type": "Microsoft.AzureAD/RiskyServicePrincipal",
                    "location": "",
                    "config": {
                        "app_id": rwi.get("appId"),
                        "risk_level": rwi.get("riskLevel"),
                        "risk_state": rwi.get("riskState"),
                        "risk_detail": rwi.get("riskDetail"),
                    },
                })
        except Exception:
            pass  # P2 licence required — degrade gracefully

        # ── 17. Administrative Units ──────────────────────────────────────────
        # Requires AdministrativeUnit.Read.All
        try:
            au_data = await self._graph_get(
                "/administrativeUnits"
                "?$select=id,displayName,description,visibility,membershipType,membershipRule"
            )
            for au in (au_data.get("value") or []):
                resources.append({
                    "id": au.get("id", ""),
                    "name": au.get("displayName", ""),
                    "type": "Microsoft.AzureAD/AdministrativeUnit",
                    "location": "",
                    "config": {
                        "visibility": au.get("visibility"),             # Public | HiddenMembership
                        "membership_type": au.get("membershipType"),    # Assigned | Dynamic
                        "membership_rule": au.get("membershipRule"),
                        "description": au.get("description"),
                    },
                })
        except Exception as exc:
            logger.debug("EntraID get_resources administrative units failed: %s", exc)

        # ── 18. Groups (security & M365 — first 500) ─────────────────────────
        # Requires GroupMember.Read.All
        try:
            grp_data = await self._graph_get(
                "/groups"
                "?$select=id,displayName,groupTypes,securityEnabled,mailEnabled"
                ",membershipRule,membershipRuleProcessingState,visibility,createdDateTime"
                "&$top=500"
            )
            for g in (grp_data.get("value") or []):
                group_types = g.get("groupTypes") or []
                resources.append({
                    "id": g.get("id", ""),
                    "name": g.get("displayName", ""),
                    "type": "Microsoft.AzureAD/Group",
                    "location": "",
                    "config": {
                        "security_enabled": g.get("securityEnabled"),
                        "mail_enabled": g.get("mailEnabled"),
                        "is_dynamic": "DynamicMembership" in group_types,
                        "is_unified": "Unified" in group_types,         # M365 group
                        "visibility": g.get("visibility"),              # Public | Private | HiddenMembership
                        "membership_rule": g.get("membershipRule"),
                        "membership_rule_state": g.get("membershipRuleProcessingState"),
                        "created_at": g.get("createdDateTime"),
                    },
                })
        except Exception as exc:
            logger.debug("EntraID get_resources groups failed: %s", exc)

        return resources

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
            logger.warning("_check_legacy_authentication failed: %s", exc)
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
            if exc.response.status_code == 403:
                logger.info(
                    "_check_identity_protection_risky_users: 403 Forbidden — "
                    "Entra ID Identity Protection requires a P2 licence."
                )
            else:
                logger.warning("_check_identity_protection_risky_users failed: %s", exc)
        except Exception as exc:
            logger.warning("_check_identity_protection_risky_users failed: %s", exc)
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
            if exc.response.status_code == 403:
                logger.info(
                    "_check_identity_protection_risky_signins: 403 Forbidden — "
                    "Entra ID Identity Protection requires a P2 licence."
                )
            else:
                logger.warning("_check_identity_protection_risky_signins failed: %s", exc)
        except Exception as exc:
            logger.warning("_check_identity_protection_risky_signins failed: %s", exc)
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
            logger.warning("_check_break_glass_accounts failed: %s", exc)
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
            logger.warning("_check_admin_consent_policy failed: %s", exc)
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
            logger.warning("_check_enterprise_applications failed: %s", exc)
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
            logger.warning("_check_authentication_methods_policy failed: %s", exc)
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
            logger.warning("_check_app_registration_owners failed: %s", exc)
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
            if exc.response.status_code == 403:
                logger.info(
                    "_check_sign_in_anomalies: 403 Forbidden — AuditLog.Read.All permission required."
                )
            else:
                logger.warning("_check_sign_in_anomalies failed: %s", exc)
        except Exception as exc:
            logger.warning("_check_sign_in_anomalies failed: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Remaining abstract implementations
    # ------------------------------------------------------------------

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []  # Identity posture is covered in config review

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
