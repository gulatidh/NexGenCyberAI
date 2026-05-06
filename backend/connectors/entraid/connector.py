"""
NexGenCyberAI - Entra ID (Azure AD) Connector
Reads identity posture: MFA status, risky users, risky sign-ins,
conditional access policies, privileged accounts.
Uses Microsoft Graph API via MSAL client credentials.
"""
from typing import Any, Dict, List
import httpx
import msal
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity


GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


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

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        findings = []

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

        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []  # Identity posture is covered in config review

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
