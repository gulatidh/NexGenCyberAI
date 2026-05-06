"""
NexGenCyberAI - Framework Compliance Agent
Maps findings to NIST CSF, NIST 800-53, CIS v8, and GDPR controls.
Calculates compliance scores per control family and generates gap reports.
"""
from langchain.tools import Tool
from typing import Any, Dict, List
from agents.base_agent import BaseAgent

# ── NIST CSF Function → Category → Control mapping (abbreviated) ───────────────

NIST_CSF_CONTROLS = {
    "ID.AM-1": "Physical devices and systems inventoried",
    "ID.AM-2": "Software platforms and applications inventoried",
    "ID.RA-1": "Asset vulnerabilities identified and documented",
    "PR.AC-1": "Identities and credentials managed for authorised users",
    "PR.AC-4": "Access permissions managed, incorporating least privilege",
    "PR.AC-7": "Users, devices, and assets authenticated",
    "PR.DS-1": "Data-at-rest protected",
    "PR.DS-2": "Data-in-transit protected",
    "PR.IP-1": "Baseline configuration established",
    "DE.AE-1": "Network operations baseline established",
    "DE.CM-1": "Network monitored to detect potential events",
    "DE.CM-7": "Monitoring for unauthorised personnel, connections, devices, software",
    "RS.RP-1": "Response plan executed during or after incident",
    "RS.CO-2": "Incidents reported consistent with criteria",
    "RC.RP-1": "Recovery plan executed during or after incident",
}

# ── CIS Controls v8 ────────────────────────────────────────────────────────────

CIS_V8_CONTROLS = {
    "CIS 1.1": "Establish and Maintain Detailed Enterprise Asset Inventory",
    "CIS 2.1": "Establish and Maintain Software Inventory",
    "CIS 3.3": "Configure Data Access Control Lists",
    "CIS 4.1": "Establish Secure Configuration Process",
    "CIS 5.2": "Use Unique Passwords",
    "CIS 5.4": "Restrict Administrator Privileges",
    "CIS 6.1": "Establish IAM Infrastructure",
    "CIS 7.1": "Establish and Maintain Vulnerability Management Process",
    "CIS 9.2": "Ensure Only Approved Ports, Protocols, Services Running",
    "CIS 10.1": "Deploy and Maintain Anti-Malware Software",
    "CIS 12.1": "Ensure Network Infrastructure is Up-to-Date",
    "CIS 14.6": "Protect Information through Access Control Lists",
    "CIS 16.1": "Establish and Maintain Application Security Program",
}

# ── GDPR Articles ──────────────────────────────────────────────────────────────

GDPR_ARTICLES = {
    "Art.5": "Principles relating to processing of personal data",
    "Art.17": "Right to erasure (right to be forgotten)",
    "Art.25": "Data protection by design and by default",
    "Art.32": "Security of processing",
    "Art.33": "Notification of breach to supervisory authority",
    "Art.35": "Data protection impact assessment",
}


def _map_findings_to_nist(findings_json: str) -> str:
    """Map each finding to NIST CSF controls via control_id field."""
    import json
    try:
        findings = json.loads(findings_json)
    except Exception:
        return "Invalid JSON"
    coverage: Dict[str, List[str]] = {k: [] for k in NIST_CSF_CONTROLS}
    unmapped = []
    for f in findings:
        ctrl = f.get("control_id", "")
        if ctrl in coverage:
            coverage[ctrl].append(f.get("title", ""))
        else:
            unmapped.append(ctrl)
    lines = [f"{ctrl}: {NIST_CSF_CONTROLS[ctrl]} — {len(v)} finding(s)" for ctrl, v in coverage.items() if v]
    score = round((len(NIST_CSF_CONTROLS) - len([c for c in coverage if coverage[c]])) / len(NIST_CSF_CONTROLS) * 100, 1)
    return f"NIST CSF Compliance Score: {score}%\nGaps:\n" + "\n".join(lines) if lines else f"NIST CSF Score: {score}% — No violations found"


def _map_findings_to_cis(findings_json: str) -> str:
    """Map findings to CIS Controls v8."""
    import json
    try:
        findings = json.loads(findings_json)
    except Exception:
        return "Invalid JSON"
    failed_controls = set()
    for f in findings:
        ctrl = f.get("control_id", "")
        if ctrl.startswith("CIS"):
            failed_controls.add(ctrl)
    score = round((len(CIS_V8_CONTROLS) - len(failed_controls)) / len(CIS_V8_CONTROLS) * 100, 1)
    gap_lines = [f"  FAIL: {c} — {CIS_V8_CONTROLS.get(c, c)}" for c in sorted(failed_controls)]
    return f"CIS v8 Score: {score}%\nFailed Controls:\n" + "\n".join(gap_lines) if gap_lines else f"CIS v8 Score: {score}%"


def _map_findings_to_gdpr(findings_json: str) -> str:
    """Identify GDPR-relevant findings."""
    import json
    try:
        findings = json.loads(findings_json)
    except Exception:
        return "Invalid JSON"
    gdpr_findings = [
        f for f in findings
        if any(kw in (f.get("title", "") + f.get("description", "")).lower()
               for kw in ["personal data", "encryption", "breach", "pii", "data protection", "tls", "ssl"])
    ]
    score = max(0, 100 - len(gdpr_findings) * 5)
    lines = [f"  Art.32 — {f.get('title','')} ({f.get('severity','')})" for f in gdpr_findings[:10]]
    return f"GDPR Compliance Score: {score}%\nRelevant Findings:\n" + "\n".join(lines) if lines else f"GDPR Score: {score}% — No violations detected"


class FrameworkAgent(BaseAgent):
    agent_name = "FrameworkComplianceAgent"
    domain = "security framework compliance (NIST, CIS, GDPR)"
    objective = (
        "Map security findings to NIST CSF, NIST 800-53, CIS v8, and GDPR controls. "
        "Calculate compliance scores, identify control gaps, and produce an executive summary."
    )

    def _default_tools(self) -> List[Tool]:
        return [
            Tool(name="map_to_nist_csf", func=_map_findings_to_nist,
                 description="Map findings to NIST CSF controls. Input: JSON array of findings."),
            Tool(name="map_to_cis_v8", func=_map_findings_to_cis,
                 description="Map findings to CIS Controls v8. Input: JSON array of findings."),
            Tool(name="map_to_gdpr", func=_map_findings_to_gdpr,
                 description="Identify GDPR-relevant findings. Input: JSON array of findings."),
        ]

    async def assess_compliance(
        self,
        findings: List[Dict],
        framework: str,
        client_name: str,
    ) -> Dict[str, Any]:
        import json
        findings_json = json.dumps(findings)

        # Run local rule-based mapping
        nist_result = _map_findings_to_nist(findings_json)
        cis_result = _map_findings_to_cis(findings_json)
        gdpr_result = _map_findings_to_gdpr(findings_json)

        input_data = {
            "task": "framework_compliance",
            "client": client_name,
            "framework": framework,
            "nist_analysis": nist_result,
            "cis_analysis": cis_result,
            "gdpr_analysis": gdpr_result,
            "instructions": (
                "1. Identify the most critical control gaps. "
                "2. Estimate compliance maturity level (Initial/Developing/Defined/Managed/Optimising). "
                "3. List top 5 recommended controls to implement first. "
                "4. Provide a compliance roadmap for the next 90 days."
            ),
        }
        result = await self.run({"input": json.dumps(input_data)})
        result.update({
            "nist_csf": nist_result,
            "cis_v8": cis_result,
            "gdpr": gdpr_result,
        })
        return result
