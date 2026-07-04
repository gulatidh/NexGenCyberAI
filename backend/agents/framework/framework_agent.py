"""
NexGenCyberAI - Framework Compliance Agent
Security governance and compliance architect persona.
Assesses posture against NIST CSF 2.0, CIS Controls v8, ISO 27001:2022, PCI DSS 4.0, SOC 2.
Produces tier-scored compliance assessments with gap analysis and control roadmaps.
"""
from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class FrameworkAgent(BaseAgent):
    """Framework Compliance Agent.

    Assesses security posture against compliance frameworks using evidence from
    vulnerability and configuration findings. Scores each framework function on a
    0-4 tier scale and computes overall compliance scores.
    """

    agent_name = "FrameworkAgent"
    domain = "security framework compliance (NIST CSF 2.0, CIS v8, ISO 27001:2022, PCI DSS 4.0)"
    objective = (
        "Assess security posture against compliance frameworks. "
        "Score framework functions on a 0-4 tier scale. Identify control gaps with evidence."
    )

    def system_prompt(self) -> str:
        return """## Role: Security Governance & Compliance Architect

You are a security governance and compliance architect with 20 years of experience
assessing organisations against global security frameworks. You have led compliance
programs for Fortune 100 companies, regulated financial institutions, healthcare
providers, and government agencies.

### Framework Expertise
You are certified and deeply proficient in:
- **NIST CSF 2.0** — 6 Functions (GV, ID, PR, DE, RS, RC), 22 Categories, 106 Subcategories
  - Governance (GV): Organisational context, risk management strategy, oversight
  - Identify (ID): Asset management, risk assessment, improvement
  - Protect (PR): Identity management, access control, awareness, data security, platform security
  - Detect (DE): Continuous monitoring, adverse event analysis
  - Respond (RS): Response planning, analysis, containment, recovery
  - Recover (RC): Recovery planning, improvements, communications
  - Tiers 0-4: Partial → Risk-Informed → Repeatable → Adaptive
- **CIS Controls v8** — 18 Controls, 153 Safeguards in 3 Implementation Groups (IG1/IG2/IG3)
  - Format: "CIS.7.1" (Control 7, Safeguard 1)
- **ISO 27001:2022** — 4 Organisational, 8 People, 14 Physical, 34 Technological controls
  - Format: "A.8.1" (Annex A, Control 8.1)
- **PCI DSS 4.0** — 12 Requirements with 250+ testing procedures
  - Requirement 6.3: Vulnerability management; Requirement 8: Authentication
- **SOC 2 Type II** — Trust Services Criteria: CC, A, C, PI, P

### Scoring Methodology
For NIST CSF 2.0, score each function on a 0-4 tier scale:
- Tier 0 (None): No evidence of implementation
- Tier 1 (Partial): Ad hoc, reactive implementation
- Tier 2 (Risk-Informed): Approved policy exists, inconsistent implementation
- Tier 3 (Repeatable): Formally documented, consistently applied, organisation-wide
- Tier 4 (Adaptive): Continuously improved, threat-adaptive, integrated with supply chain

Overall compliance score = (average tier across all functions) × 25, capped at 100.

### Control ID Format Rules (CRITICAL)
- NIST CSF 2.0: Zero-padded sub-category IDs — PR.AA-01 (not PR.AA-1), DE.CM-01 (not DE.CM-1)
  RS.RP-01, RC.RP-01, GV.OC-01, ID.AM-01, ID.RA-01, PR.DS-01, DE.AE-01
- CIS Controls v8: "CIS.7.1" format (Control number . Safeguard number)
- ISO 27001: "A.8.1" format
- PCI DSS: "PCI.6.3.1" format (Requirement . Sub-requirement)
NEVER use un-padded IDs like PR.AA-1, DE.CM-7, RS.RP-1.

### Gap Analysis Methodology
You map framework gaps to specific findings evidence. For every gap identified, you
must cite at least one finding from the provided data as evidence. You distinguish
between: Implemented, Partially Implemented, Not Implemented, Not Assessed.

### Conduct
You write in a precise, third-person compliance report tone. Every tier score and
gap identification is grounded in evidence from the provided findings. You never
assert gaps without citing evidence. You never invent control IDs."""

    async def assess_compliance(
        self,
        findings: List[Dict],
        framework: str,
        client_name: str,
    ) -> Dict[str, Any]:
        """Assess compliance posture against the specified framework.

        Args:
            findings:    List of finding dicts from the scan pipeline.
            framework:   Framework name (e.g., 'nist_csf', 'cis_v8', 'iso_27001').
            client_name: Client organisation name.

        Returns:
            Structured dict with overall_score key for orchestrator compatibility.
        """
        if not self._has_provider():
            result = self._fallback_analysis(findings)
            result["overall_score"] = 0
            return result

        # ── Pre-compute deterministic metrics ──────────────────────────────────
        confidence, pct = self._compute_data_completeness(findings)
        sev_counts = _count_severities(findings)

        # Group findings by control_id
        controls_by_id: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            cid = f.get("control_id")
            if cid:
                controls_by_id[cid].append(f)

        unique_controls = list(controls_by_id.keys())
        # Coverage pct: unique controls with findings as proportion of expected 20
        coverage_pct = min(100, round((len(unique_controls) / 20) * 100))

        # Top breached controls (by finding count)
        top_controls = sorted(
            [(cid, len(fs)) for cid, fs in controls_by_id.items()],
            key=lambda x: -x[1],
        )[:15]

        framework_display = _normalise_framework_name(framework)

        # ── Build prompts ──────────────────────────────────────────────────────
        system = (
            self.system_prompt()
            + "\n\n"
            + self.anti_hallucination_directive()
            + "\n\n"
            + self.consulting_packaging_directive()
        )
        if self.extra_context:
            system += f"\n\n## Framework Controls Reference\n{self.extra_context}"

        user = f"""## Framework Compliance Assessment Input: {client_name}

### Dataset Overview
- **Client:** {client_name}
- **Framework:** {framework_display}
- **Total findings:** {len(findings)}
- **Data confidence:** {confidence} ({pct}% completeness)
- **Unique controls breached:** {len(unique_controls)}
- **Control coverage pct (findings / 20 expected controls):** {coverage_pct}%

### Severity Distribution
| Severity | Count |
|----------|-------|
| CRITICAL | {sev_counts['critical']} |
| HIGH     | {sev_counts['high']} |
| MEDIUM   | {sev_counts['medium']} |
| LOW      | {sev_counts['low']} |
| INFO     | {sev_counts['info']} |

### Controls with Most Findings
{_format_control_table(top_controls)}

### All Unique Control IDs Breached
{', '.join(unique_controls[:40]) if unique_controls else 'None recorded'}

### Instructions
Produce a {framework_display} compliance assessment for {client_name}.

The `output` field must contain 400-800 words of markdown covering:
1. **{framework_display} Posture Overview** — overall tier/score and what it means
2. **Function/Domain Scoring** — score each major function (GV/ID/PR/DE/RS/RC for NIST CSF 2.0)
   on the 0-4 tier scale with evidence citations from the findings data above
3. **Critical Control Gaps** — top 5 gaps with evidence and remediation priority
4. **Compliance Roadmap** — 30/90/180-day actions to improve compliance tier
5. **Audit Readiness** — what evidence is available vs. what auditors will require

For maturity_indicators, use NIST CSF 2.0 function names as sub_domains:
  GV (Govern), ID (Identify), PR (Protect), DE (Detect), RS (Respond), RC (Recover)
Each with tier (0-4) and evidence citing actual findings.

Overall compliance score = (average tier) × 25. Report this as overall_tier in maturity_indicators.

Finding IDs must use prefix {_get_finding_prefix(framework)} with sub-domains matching
framework functions.

IMPORTANT: Use zero-padded NIST CSF 2.0 IDs: PR.AA-01 not PR.AA-1, DE.CM-01 not DE.CM-1.

Use data_confidence="{confidence}" and data_completeness_pct={pct} exactly as given."""

        try:
            result = await self._call_llm(system, user)
        except Exception as exc:
            logger.error(f"FrameworkAgent LLM error: {exc}")
            result = self._fallback_analysis(findings)

        # Ensure overall_score is always present for orchestrator
        overall_tier = result.get("maturity_indicators", {}).get("overall_tier", 1)
        result["overall_score"] = min(100, max(0, int(overall_tier * 25)))
        return result


# ── Module-level helpers ───────────────────────────────────────────────────────

def _count_severities(findings: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


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


def _get_finding_prefix(framework: str) -> str:
    mapping = {
        "nist_csf": "NIST",
        "nist": "NIST",
        "cis_v8": "CIS",
        "cis": "CIS",
        "iso_27001": "ISO",
        "pci_dss": "PCI",
        "soc2": "SOC",
        "hipaa": "HIPAA",
        "gdpr": "GRC",
    }
    return mapping.get((framework or "").lower(), "GRC")


def _format_control_table(top_controls: List[tuple]) -> str:
    if not top_controls:
        return "No control IDs recorded in findings."
    lines = ["| Control ID | Finding Count |", "|------------|---------------|"]
    for cid, count in top_controls:
        lines.append(f"| {cid} | {count} |")
    return "\n".join(lines)
