"""
NexGenCyberAI - Agent Orchestrator
Coordinates all agents in the correct order for a full scan lifecycle.
Uses LangGraph for stateful multi-agent orchestration.
"""
from typing import Any, Dict, List, Optional
from agents.risk.risk_agent import RiskManagementAgent
from agents.vascan.vascan_agent import VAScanAgent
from agents.framework.framework_agent import FrameworkAgent
from agents.threat.threat_intel_agent import ThreatIntelAgent
from agents.remediation.remediation_agent import RemediationAgent
from agents.compliance.compliance_agent import ComplianceMonitorAgent
import logging

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """
    Orchestrates the full cybersecurity assessment workflow:
    1. VA Scan Agent      — enumerate vulnerabilities
    2. Framework Agent    — map to controls
    3. Threat Intel Agent — correlate with TTPs
    4. Risk Agent         — calculate risk scores
    5. Remediation Agent  — generate playbooks
    6. Compliance Agent   — produce audit report
    """

    def __init__(self):
        self.vascan = VAScanAgent()
        self.framework = FrameworkAgent()
        self.threat_intel = ThreatIntelAgent()
        self.risk = RiskManagementAgent()
        self.remediation = RemediationAgent()
        self.compliance = ComplianceMonitorAgent()

    async def run_full_assessment(
        self,
        findings: List[Dict],
        client_name: str,
        framework: str = "nist_csf",
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run all agents sequentially and return a consolidated report.
        In production this can be parallelised where dependencies allow.
        """
        report: Dict[str, Any] = {
            "scan_id": scan_id,
            "client": client_name,
            "framework": framework,
            "findings_count": len(findings),
        }
        logger.info(f"[Orchestrator] Starting full assessment for {client_name} — {len(findings)} findings")

        # Stage 1: VA Analysis
        try:
            report["va_analysis"] = await self.vascan.analyse_vulnerabilities(findings, client_name)
            logger.info("[Orchestrator] VA analysis complete")
        except Exception as exc:
            logger.error(f"VA agent error: {exc}")
            report["va_analysis"] = {"error": str(exc)}

        # Stage 2: Framework Mapping
        try:
            report["framework_analysis"] = await self.framework.assess_compliance(findings, framework, client_name)
            logger.info("[Orchestrator] Framework analysis complete")
        except Exception as exc:
            report["framework_analysis"] = {"error": str(exc)}

        # Stage 3: Threat Intel
        try:
            report["threat_intel"] = await self.threat_intel.enrich_findings(findings, client_name)
            logger.info("[Orchestrator] Threat intel complete")
        except Exception as exc:
            report["threat_intel"] = {"error": str(exc)}

        # Stage 4: Risk Assessment
        try:
            report["risk_analysis"] = await self.risk.analyse_scan(findings, client_name)
            logger.info("[Orchestrator] Risk analysis complete")
        except Exception as exc:
            report["risk_analysis"] = {"error": str(exc)}

        # Stage 5: Remediation Playbooks
        try:
            report["remediation"] = await self.remediation.generate_playbook(findings, client_name)
            logger.info("[Orchestrator] Remediation playbooks generated")
        except Exception as exc:
            report["remediation"] = {"error": str(exc)}

        # Stage 6: Compliance Audit Report
        try:
            assessment_data = {
                "controls_total": len(set(f.get("control_id") for f in findings if f.get("control_id"))),
                "controls_passed": 0,
                "overall_score": report.get("framework_analysis", {}).get("overall_score", 0),
            }
            report["audit_report"] = await self.compliance.generate_audit_report(
                assessment_data, client_name, framework
            )
            logger.info("[Orchestrator] Audit report generated")
        except Exception as exc:
            report["audit_report"] = {"error": str(exc)}

        logger.info(f"[Orchestrator] Full assessment complete for {client_name}")
        return report

    async def run_single_agent(
        self,
        agent_type: str,
        findings: List[Dict],
        client_name: str,
        framework: str = "nist_csf",
    ) -> Dict[str, Any]:
        """Run a single agent by type."""
        agents = {
            "va_scanner": lambda: self.vascan.analyse_vulnerabilities(findings, client_name),
            "framework_analyst": lambda: self.framework.assess_compliance(findings, framework, client_name),
            "threat_intel": lambda: self.threat_intel.enrich_findings(findings, client_name),
            "risk_manager": lambda: self.risk.analyse_scan(findings, client_name),
            "remediation": lambda: self.remediation.generate_playbook(findings, client_name),
            "compliance_monitor": lambda: self.compliance.generate_audit_report({}, client_name, framework),
        }
        runner = agents.get(agent_type)
        if not runner:
            return {"error": f"Unknown agent type: {agent_type}"}
        return await runner()
