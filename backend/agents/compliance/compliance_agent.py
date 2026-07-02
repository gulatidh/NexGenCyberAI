"""
NexGenCyberAI - Compliance Monitoring Agent
GRC advisor and audit specialist persona.
Assesses audit readiness, identifies policy gaps, maps findings to compliance obligations.
Supports: NIST CSF 2.0, ISO 27001:2022, PCI DSS 4.0, SOC 2, HIPAA, GDPR, CIS Controls v8.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class ComplianceMonitorAgent(BaseAgent):
    """Compliance Monitoring Agent.

    Assesses audit readiness, maps technical findings to compliance obligations,
    identifies policy gaps, and produces compliance dashboards.
    """

    agent_name = "ComplianceMonitorAgent"
    domain = "regulatory compliance and audit management"
    objective = (
        "Assess audit readiness and map technical findings to regulatory obligations. "
        "Produce compliance dashboards with control coverage percentages and audit readiness scores."
    )

    def system_prompt(self) -> str:
        return """## Role: GRC Advisor & Audit Specialist

You are a Governance, Risk, and Compliance (GRC) advisor and audit specialist with
22 years of experience supporting external audits, regulatory examinations, and
internal compliance assessments across global organisations in financial services,
healthcare, retail, and technology sectors.

### Framework & Regulatory Expertise
You hold in-depth expertise across:
- **NIST CSF 2.0** — Cybersecurity Framework with 6 functions and 106 subcategories
- **ISO 27001:2022** — Information Security Management System with 93 controls across
  4 domains and Annex A (Organisational, People, Physical, Technological)
- **PCI DSS 4.0** — Payment Card Industry Data Security Standard, 12 Requirements,
  250+ test procedures, applicable to all entities that store, process, or transmit cardholder data
  - Key: Req 6.3 (vulnerability management), Req 8 (authentication), Req 10 (logging)
- **SOC 2 Type II** — Trust Services Criteria (CC=Common Criteria, A=Availability,
  C=Confidentiality, PI=Processing Integrity, P=Privacy), 12-month observation period
- **HIPAA Security Rule** — 45 CFR Part 164:
  - §164.312(a)(1): Access controls (addressable)
  - §164.312(b): Audit controls (required)
  - §164.312(c)(1): Integrity (addressable)
  - §164.312(d): Authentication (required)
  - §164.312(e)(1): Transmission security (addressable)
- **GDPR Article 32** — Security of processing: appropriate technical and organisational
  measures including encryption, confidentiality, integrity, availability, resilience,
  restoration capability, and testing procedures
- **CIS Controls v8** — 18 Controls, 153 Safeguards. Format: "CIS.7.1"

### Compliance Implementation Status Classifications
You always distinguish between:
- **Implemented**: Control is in place, evidence is available, audit-ready
- **Partially Implemented**: Control exists but has gaps; additional work required
- **Not Implemented**: Control is absent; immediate remediation required
- **Not Assessed**: Insufficient evidence to determine implementation status

### Audit Readiness Assessment Methodology
Audit readiness score (0-100) is computed as:
  (implemented_controls / total_applicable_controls) × 100
Adjusted down by:
  -10 points per CRITICAL finding that maps to a mandatory control
  -5 points per HIGH finding that maps to a required control
Floored at 0.

### Compliance Dashboard Structure
For each framework you produce:
1. Overall compliance percentage (controls implemented / total applicable)
2. Control gap list (specific failed controls with evidence)
3. Audit readiness score (0-100) with evidence quality assessment
4. Evidence inventory (what exists vs. what auditors will require)
5. Policy gap analysis (policies referenced but not evidenced)

### Regulatory Obligation Precision
You cite specific regulatory requirements with precision:
- GDPR Article 32(1)(a): pseudonymisation and encryption
- GDPR Article 32(1)(b): ongoing confidentiality, integrity, availability, resilience
- GDPR Article 32(1)(d): regular testing and evaluation
- HIPAA §164.312(a)(1): Unique user identification, emergency access, auto-logoff, encryption
- PCI DSS 6.3.1: Installed security vulnerabilities identified and ranked
- PCI DSS 8.3.1: Multi-factor authentication for all access into the cardholder data environment
Never assert compliance or non-compliance without citing evidence from the provided data.

### Conduct
You write in formal audit report language appropriate for a Board, Audit Committee,
or external auditor audience. Every gap assertion is evidenced from the provided data.
You distinguish clearly between mandatory and addressable requirements in HIPAA,
and between required and recommended controls in other frameworks."""

    async def generate_audit_report(
        self,
        assessment_data: Dict,
        client_name: str,
        framework: str,
    ) -> Dict[str, Any]:
        """Generate a compliance audit report from assessment data.

        Args:
            assessment_data: Dict containing controls_total, controls_passed,
                             overall_score (optional), and findings (optional).
            client_name:     Client organisation name.
            framework:       Framework name (e.g., 'nist_csf', 'pci_dss').

        Returns:
            Structured dict with compliance_dashboard, audit_readiness_assessment,
            policy_gaps, and regulatory_obligations.
        """
        if not self._has_provider():
            result = self._fallback_analysis(
                assessment_data.get("findings", [])
            )
            result["score_summary"] = _build_score_summary(assessment_data)
            return result

        # ── Pre-compute deterministic metrics ──────────────────────────────────
        findings = assessment_data.get("findings", [])
        confidence, pct = self._compute_data_completeness(findings)
        sev_counts = _count_severities(findings)

        controls_total = assessment_data.get("controls_total", 0)
        controls_passed = assessment_data.get("controls_passed", 0)
        overall_score = assessment_data.get("overall_score", 0)

        # Compute compliance pct
        compliance_pct = (
            round(controls_passed / controls_total * 100, 1)
            if controls_total > 0
            else 0
        )

        # Compute audit readiness score
        audit_readiness = min(100, max(0, compliance_pct))
        audit_readiness -= sev_counts.get("critical", 0) * 10
        audit_readiness -= sev_counts.get("high", 0) * 5
        audit_readiness = max(0, audit_readiness)

        score_summary = _build_score_summary(assessment_data)
        framework_display = _normalise_framework_name(framework)

        # ── Build prompts ──────────────────────────────────────────────────────
        system = (
            self.system_prompt()
            + "\n\n"
            + self.anti_hallucination_directive()
            + "\n\n"
            + self.consulting_packaging_directive()
        )

        user = f"""## Compliance Audit Report Input: {client_name}

### Dataset Overview
- **Client:** {client_name}
- **Framework:** {framework_display}
- **Data confidence:** {confidence} ({pct}% completeness)

### Assessment Summary
- **Controls Total Assessed:** {controls_total}
- **Controls Passed:** {controls_passed}
- **Compliance Percentage:** {compliance_pct}%
- **Overall Posture Score (from framework agent):** {overall_score}/100
- **Pre-computed Audit Readiness Score:** {audit_readiness}/100
  (Formula: compliance_pct - critical_count×10 - high_count×5, floored at 0)
- **Score Summary:** {score_summary}

### Severity Distribution from Findings
| Severity | Count | Compliance Impact |
|----------|-------|-------------------|
| CRITICAL | {sev_counts['critical']} | -10 pts per control failure |
| HIGH     | {sev_counts['high']} | -5 pts per control failure |
| MEDIUM   | {sev_counts['medium']} | -2 pts per control failure |
| LOW      | {sev_counts['low']} | -0 pts |

### Findings (for control mapping)
{json.dumps(findings[:20], indent=2) if findings else 'No findings provided — assessment data only.'}

### Instructions
Produce a {framework_display} compliance audit report for {client_name}.

The `output` field must contain 400-800 words of markdown covering:
1. **Compliance Posture Overview** — {compliance_pct}% compliance, audit readiness {audit_readiness}/100
2. **Control Coverage Analysis** — which domains/functions are implemented vs. gaps
3. **Audit Readiness Assessment** — what evidence exists, what gaps remain before audit
4. **Policy Gap Analysis** — required policies that are evidenced as missing
5. **Regulatory Obligations Mapping** — map specific findings to regulatory clauses
   (e.g., GDPR Art.32(1)(a), HIPAA §164.312, PCI DSS 6.3.1)
6. **Pre-Audit Action Plan** — prioritised actions to close audit readiness gaps

Finding IDs must use prefix GRC with sub-domains:
- GRC-CM-NNN: Compliance Mapping
- GRC-AU-NNN: Audit Readiness
- GRC-PL-NNN: Policy Gaps
- GRC-RR-NNN: Regulatory Requirements

maturity_indicators sub_domains must include: policy_framework, control_implementation,
audit_readiness, continuous_compliance.

Use data_confidence="{confidence}" and data_completeness_pct={pct} exactly as given."""

        try:
            result = await self._call_llm(system, user)
        except Exception as exc:
            logger.error(f"ComplianceMonitorAgent LLM error: {exc}")
            result = self._fallback_analysis(findings)

        result["score_summary"] = score_summary
        result["audit_readiness_score"] = audit_readiness
        return result


# ── Module-level helpers ───────────────────────────────────────────────────────

def _count_severities(findings: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _build_score_summary(assessment_data: Dict) -> str:
    """Build human-readable compliance score summary string."""
    total = assessment_data.get("controls_total", 0)
    passed = assessment_data.get("controls_passed", 0)
    overall = assessment_data.get("overall_score", 0)

    if total == 0:
        return f"Overall Posture Score: {overall}/100 | No controls assessed"

    pct = round(passed / total * 100, 1)
    level = (
        "Optimising" if pct >= 90
        else "Managed" if pct >= 75
        else "Defined" if pct >= 60
        else "Developing" if pct >= 40
        else "Initial"
    )
    return (
        f"Compliance: {pct}% | Maturity: {level} | "
        f"Passed: {passed}/{total} | Posture Score: {overall}/100"
    )


def _normalise_framework_name(framework: str) -> str:
    mapping = {
        "nist_csf": "NIST CSF 2.0",
        "nist_csf_2": "NIST CSF 2.0",
        "nist": "NIST CSF 2.0",
        "cis_v8": "CIS Controls v8",
        "cis": "CIS Controls v8",
        "iso_27001": "ISO 27001:2022",
        "iso27001": "ISO 27001:2022",
        "pci_dss": "PCI DSS 4.0",
        "pci": "PCI DSS 4.0",
        "soc2": "SOC 2 Type II",
        "soc_2": "SOC 2 Type II",
        "hipaa": "HIPAA Security Rule",
        "gdpr": "GDPR Article 32",
    }
    return mapping.get((framework or "").lower(), framework.upper())
