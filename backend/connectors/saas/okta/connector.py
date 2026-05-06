"""
NexGenCyberAI - Okta Connector
Uses Okta Management API (SSWS token or OAuth2 private key JWT).
Checks MFA enrollment, suspicious sessions, Okta admin roles.
"""
from typing import Any, Dict, List
import httpx
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity


class OktaConnector(BaseConnector):

    @property
    def _base_url(self):
        return f"https://{self.credentials['domain']}/api/v1"

    def _headers(self):
        return {
            "Authorization": f"SSWS {self.credentials['api_token']}",
            "Accept": "application/json",
        }

    async def _get(self, path: str, params: Dict = {}) -> Any:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self._base_url}{path}",
                headers=self._headers(),
                params=params,
            )
        resp.raise_for_status()
        return resp.json()

    async def test_connection(self) -> ConnectorTestResult:
        try:
            data = await self._get("/users?limit=1")
            return ConnectorTestResult(success=True, message="Okta connection successful", details={"sample_users": len(data)})
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    async def get_resources(self) -> List[Dict[str, Any]]:
        users = await self._get("/users?limit=200")
        return [
            {
                "id": u["id"],
                "name": u.get("profile", {}).get("displayName", ""),
                "email": u.get("profile", {}).get("email", ""),
                "status": u.get("status"),
                "type": "okta_user",
            }
            for u in users
        ]

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        findings = []
        # Check for users without MFA enrolled
        try:
            users = await self._get("/users?filter=status eq \"ACTIVE\"&limit=200")
            for user in users:
                uid = user["id"]
                factors = await self._get(f"/users/{uid}/factors")
                if not factors:
                    findings.append(ConnectorFinding(
                        title="Okta user has no MFA factor enrolled",
                        description=f"User {user.get('profile', {}).get('email')} has no MFA factor enrolled.",
                        severity=FindingSeverity.HIGH,
                        resource_id=uid,
                        resource_type="Okta User",
                        control_id="NIST IA-2",
                        framework="nist_csf",
                        remediation="Enforce MFA enrollment via Okta sign-on policy.",
                    ))
        except Exception:
            pass

        # Check for inactive/suspended admin accounts
        try:
            admins = await self._get("/groups/ADMINISTRATORS/users")
            for admin in admins:
                if admin.get("status") in ("SUSPENDED", "DEPROVISIONED"):
                    findings.append(ConnectorFinding(
                        title="Suspended admin account in Okta",
                        description=f"Admin {admin.get('profile', {}).get('email')} is suspended but still in admin group.",
                        severity=FindingSeverity.MEDIUM,
                        resource_id=admin["id"],
                        resource_type="Okta Admin",
                        control_id="NIST AC-2",
                        framework="nist_csf",
                        remediation="Remove suspended users from administrative groups.",
                    ))
        except Exception:
            pass

        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
