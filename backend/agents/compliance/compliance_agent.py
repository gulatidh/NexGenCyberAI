"""
NexGenCyberAI - Compliance Monitoring Agent
Continuously monitors for compliance drift, generates audit reports,
and tracks control effectiveness over time.
"""
from typing import Any, Dict, List
from ..base_agent import BaseAgent
from langchain.tools import Tool
import json


def _calculate_compliance_score(framework_data: str) -> str:
    try:
        data = json.loads(framework_data)
        total = data.get("controls_total", 0)
        passed = data.get("controls_passed", 0)
        if total == 0:
            return "No controls assessed"
        score = round(passed / total * 100, 1)
        level = (
            "Optimising" if score >= 90 else
            "Managed" if score >= 75 else
            "Defined" if score >= 60 else
            "Developing" if score >= 40 else
            "Initial"
        )
        return f"Compliance Score: {score}% | Maturity: {level} | Passed: {passed}/{total}"
    except Exception as exc:
        return str(exc)


def _drift_analysis(before_json: str, after_json: str) -> str:
    try:
        before = json.loads(before_json)
        after = json.loads(after_json)
        before_score = before.get("overall_score", 0)
        after_score = after.get("overall_score", 0)
        delta = round(after_score - before_score, 1)
        direction = "improved" if delta >= 0 else "degraded"
        return (
            f"Compliance {direction} by {abs(delta)}%. "
            f"Previous: {before_score}% → Current: {after_score}%"
        )
    except Exception as exc:
        return str(exc)


class ComplianceMonitorAgent(BaseAgent):
    agent_name = "ComplianceMonitorAgent"
    domain = "regulatory compliance and audit management"
    objective = (
        "Monitor compliance posture continuously. "
        "Detect compliance drift, generate audit-ready reports, "
        "and track control effectiveness trends."
    )

    def _default_tools(self) -> List[Tool]:
        return [
            Tool(
                name="calculate_compliance_score",
                func=_calculate_compliance_score,
                description="Calculate overall compliance score from assessment data. Input: JSON with controls_total and controls_passed.",
            ),
            Tool(
                name="detect_compliance_drift",
                func=lambda x: _drift_analysis(*x.split("|||")),
                description="Compare two assessment snapshots. Input: before_json|||after_json",
            ),
        ]

    async def generate_audit_report(
        self,
        assessment: Dict,
        client_name: str,
        framework: str,
    ) -> Dict[str, Any]:
        score_summary = _calculate_compliance_score(json.dumps(assessment))
        result = await self.run({
            "input": json.dumps({
                "task": "audit_report",
                "client": client_name,
                "framework": framework,
                "assessment": assessment,
                "score_summary": score_summary,
                "instructions": (
                    "1. Write an executive summary suitable for a CISO. "
                    "2. List evidence required for each failed control. "
                    "3. Identify controls at risk of drifting. "
                    "4. Recommend a continuous compliance monitoring cadence."
                ),
            })
        })
        result["score_summary"] = score_summary
        return result
