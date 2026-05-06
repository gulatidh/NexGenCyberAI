"""
NexGenCyberAI - Risk Management Agent
Analyses scan findings, calculates risk scores, prioritises risks,
and generates a risk register with mitigation recommendations.
"""
from langchain.tools import Tool
from typing import Any, Dict, List
from ..base_agent import BaseAgent


def _calculate_risk_score(likelihood: int, impact: int) -> float:
    """NIST SP 800-30 risk score matrix (1-25 scale → 0-10)."""
    return round((likelihood * impact) / 2.5, 1)


def _risk_level(score: float) -> str:
    if score >= 7: return "critical"
    if score >= 5: return "high"
    if score >= 3: return "medium"
    return "low"


def _analyse_findings_tool(findings_json: str) -> str:
    """Analyse a JSON list of findings and return a risk summary."""
    import json
    try:
        findings = json.loads(findings_json)
    except Exception:
        return "Invalid JSON input"
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    total = len(findings)
    risk_score = (
        severity_counts["critical"] * 10 +
        severity_counts["high"] * 7 +
        severity_counts["medium"] * 4 +
        severity_counts["low"] * 1
    ) / max(total, 1)
    return (
        f"Total findings: {total} | Critical: {severity_counts['critical']} | "
        f"High: {severity_counts['high']} | Medium: {severity_counts['medium']} | "
        f"Low: {severity_counts['low']} | Composite risk score: {round(risk_score, 1)}/10"
    )


def _map_to_risk_register(findings_json: str) -> str:
    """Convert findings into risk register entries."""
    import json
    try:
        findings = json.loads(findings_json)
    except Exception:
        return "Invalid JSON"
    risks = []
    for i, f in enumerate(findings[:20], 1):
        sev = f.get("severity", "low")
        likelihood = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(sev, 2)
        impact = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(sev, 2)
        score = _calculate_risk_score(likelihood, impact)
        risks.append(
            f"R{i:03d}: {f.get('title', 'Unknown')} | "
            f"Level={_risk_level(score)} | Score={score} | "
            f"Control={f.get('control_id', 'N/A')}"
        )
    return "\n".join(risks) if risks else "No risks identified"


class RiskManagementAgent(BaseAgent):
    agent_name = "RiskManagementAgent"
    domain = "risk management and threat modelling"
    objective = (
        "Analyse security findings, calculate risk scores using NIST SP 800-30 methodology, "
        "generate a prioritised risk register, and recommend mitigation strategies."
    )

    def _default_tools(self) -> List[Tool]:
        return [
            Tool(
                name="analyse_findings",
                func=_analyse_findings_tool,
                description="Analyse a JSON list of security findings and return risk metrics. Input: JSON array of findings.",
            ),
            Tool(
                name="build_risk_register",
                func=_map_to_risk_register,
                description="Convert findings JSON into a risk register. Input: JSON array of findings.",
            ),
        ]

    async def analyse_scan(self, findings: List[Dict], client_name: str) -> Dict[str, Any]:
        """High-level entry point for risk analysis after a scan."""
        import json
        input_data = {
            "task": "risk_analysis",
            "client": client_name,
            "findings": findings,
            "instructions": (
                "1. Calculate overall risk score. "
                "2. Build a risk register with top 10 items. "
                "3. Identify systemic weaknesses. "
                "4. Recommend top 3 immediate mitigations."
            ),
        }
        result = await self.run({"input": json.dumps(input_data)})
        # Supplement with local rule-based analysis
        findings_json = json.dumps(findings)
        local_summary = _analyse_findings_tool(findings_json)
        result["local_summary"] = local_summary
        result["risk_register"] = _map_to_risk_register(findings_json)
        return result
