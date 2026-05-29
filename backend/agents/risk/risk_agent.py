"""
NexGenCyberAI - Risk Management Agent
Analyses scan findings, calculates risk scores, prioritises risks,
and generates a risk register with mitigation recommendations.
"""
from langchain_core.tools import Tool
from typing import Any, Dict, List
from agents.base_agent import BaseAgent


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
    """Convert findings into risk register entries (string form for LLM tool)."""
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


def map_to_risk_register_structured(findings: list) -> list:
    """Return findings as structured risk register dicts for DB persistence."""
    result = []
    for f in findings[:20]:
        sev = f.get("severity", "low")
        likelihood = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(sev, 2)
        impact = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(sev, 2)
        score = _calculate_risk_score(likelihood, impact)
        result.append({
            "title": f.get("title", "Unknown Risk"),
            "description": f.get("description", ""),
            "risk_level": _risk_level(score),
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": score,
            "category": f.get("resource_type") or f.get("control_id") or "security",
            "status": "open",
            "finding_ref": f.get("title", ""),
        })
    return result


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
                "Produce a professional risk analysis using EXACTLY these "
                "section headers (markdown level-3), in this order:\n"
                "  ### Overall Risk Score\n"
                "  ### Top Risks\n"
                "  ### Systemic Weaknesses\n"
                "  ### Immediate Mitigations\n\n"
                "Rules:\n"
                "- Write in third-person, executive-report tone — no greetings, "
                "no 'I will', no 'we can', no questions to the user.\n"
                "- Do NOT end with offers like 'If you want, I can also...' or "
                "'Would you like me to...'. Stop after Immediate Mitigations.\n"
                "- Under each header, use concise bulleted lines.\n"
                "- For Overall Risk Score: one sentence with score and "
                "qualitative band.\n"
                "- For Top Risks: 5-10 prioritised bullets, each with risk ID, "
                "title, severity and control mapping in brackets.\n"
                "- For Immediate Mitigations: 3-5 actions, ordered by impact."
            ),
        }
        result = await self.run({"input": json.dumps(input_data)})
        # Supplement with local rule-based analysis
        findings_json = json.dumps(findings)
        local_summary = _analyse_findings_tool(findings_json)
        result["local_summary"] = local_summary
        result["risk_register"] = _map_to_risk_register(findings_json)
        return result
