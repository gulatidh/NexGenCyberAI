"""
NexGenCyberAI - Remediation Agent
Generates step-by-step remediation playbooks for findings.
Integrates with ServiceNow to create remediation tickets automatically.
"""
from langchain.tools import Tool
from typing import Any, Dict, List
import json
from agents.base_agent import BaseAgent

# Remediation KB: control → step-by-step fix
REMEDIATION_KB: Dict[str, str] = {
    "NIST AC-2": (
        "1. Audit all active accounts. "
        "2. Disable accounts inactive for >90 days. "
        "3. Enforce MFA for privileged accounts. "
        "4. Implement account lifecycle automation via HR system integration."
    ),
    "NIST IA-2": (
        "1. Enable MFA in Azure Entra ID / Okta for all users. "
        "2. Create Conditional Access policy requiring MFA for all cloud apps. "
        "3. Exclude break-glass accounts from CA but monitor them. "
        "4. Use Microsoft Authenticator or hardware FIDO2 key."
    ),
    "NIST SC-8": (
        "1. Enable TLS 1.2+ on all endpoints. "
        "2. Disable TLS 1.0, 1.1, SSL 3.0. "
        "3. Enforce HTTPS-only in Azure App Service / AWS ALB. "
        "4. Implement HSTS header."
    ),
    "CIS 5.2.1": (
        "1. Identify all privileged containers in the cluster. "
        "2. Update Kubernetes deployment specs: securityContext.privileged=false. "
        "3. Implement OPA Gatekeeper policy to reject privileged pods. "
        "4. Conduct regular pod security audit."
    ),
}


def _lookup_remediation(control_id: str) -> str:
    return REMEDIATION_KB.get(control_id, f"No remediation playbook found for {control_id}. Review vendor documentation.")


def _generate_ticket_payload(finding_json: str) -> str:
    """Generate a ServiceNow incident payload for a finding."""
    try:
        finding = json.loads(finding_json) if isinstance(finding_json, str) else finding_json
        payload = {
            "short_description": f"[NexGenCyberAI] {finding.get('title', 'Security Finding')}",
            "description": finding.get("description", ""),
            "priority": {"critical": "1", "high": "2", "medium": "3", "low": "4"}.get(
                finding.get("severity", "medium"), "3"
            ),
            "category": "security",
            "assignment_group": "Security Operations",
            "work_notes": f"Control ID: {finding.get('control_id', 'N/A')}\nRemediation: {_lookup_remediation(finding.get('control_id', ''))}",
        }
        return json.dumps(payload, indent=2)
    except Exception as exc:
        return str(exc)


class RemediationAgent(BaseAgent):
    agent_name = "RemediationAgent"
    domain = "security remediation and playbook generation"
    objective = (
        "Generate detailed, actionable remediation playbooks for each security finding. "
        "Create ServiceNow tickets automatically and track remediation progress."
    )

    def _default_tools(self) -> List[Tool]:
        return [
            Tool(
                name="lookup_remediation_kb",
                func=_lookup_remediation,
                description="Look up remediation steps for a control ID. Input: control ID string (e.g., 'NIST AC-2').",
            ),
            Tool(
                name="generate_servicenow_ticket",
                func=_generate_ticket_payload,
                description="Generate a ServiceNow ticket payload for a finding. Input: JSON finding object.",
            ),
        ]

    async def generate_playbook(self, findings: List[Dict], client_name: str) -> Dict[str, Any]:
        playbooks = {}
        tickets = []
        for f in findings[:20]:
            ctrl = f.get("control_id", "")
            if ctrl and ctrl not in playbooks:
                playbooks[ctrl] = _lookup_remediation(ctrl)
            tickets.append(_generate_ticket_payload(json.dumps(f)))

        result = await self.run({
            "input": json.dumps({
                "task": "remediation_plan",
                "client": client_name,
                "playbooks": playbooks,
                "finding_count": len(findings),
                "instructions": (
                    "1. Group remediation tasks by priority (Critical → High → Medium → Low). "
                    "2. Estimate effort (hours) per task. "
                    "3. Identify quick wins (fixes < 2h). "
                    "4. Create a 30/60/90-day remediation roadmap."
                ),
            })
        })
        result["playbooks"] = playbooks
        result["ticket_payloads"] = tickets[:5]
        return result
