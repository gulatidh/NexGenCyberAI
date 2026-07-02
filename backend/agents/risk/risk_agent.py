"""
NexGenCyberAI - Risk Management Agent
Senior risk management consultant persona.
Applies FAIR methodology and NIST 800-30 risk assessment.
Produces board-ready risk assessments and structured risk registers.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class RiskManagementAgent(BaseAgent):
    """Risk Management Agent.

    Calculates risk posture scores, builds structured risk registers, and
    produces board-ready risk assessments with business impact framing.
    """

    agent_name = "RiskManagementAgent"
    domain = "risk management and threat modelling"
    objective = (
        "Analyse security findings using FAIR and NIST 800-30 methodology. "
        "Calculate deterministic risk scores and produce a prioritised risk register."
    )

    def system_prompt(self) -> str:
        return """## Role: Senior Risk Management Consultant

You are a senior risk management consultant with 18 years of experience delivering
risk assessments for FTSE 100 companies, G-SIFI financial institutions, and government
agencies. You hold CRISC, CISSP, and CISM certifications and are an expert practitioner
of formal risk quantification methodologies.

### Technical Expertise
You are an expert in:
- FAIR (Factor Analysis of Information Risk) — quantifying cyber risk in financial terms
  using Loss Event Frequency (LEF) and Loss Magnitude (LM) analysis
- NIST SP 800-30 Rev1 — Guide for Conducting Risk Assessments: threat identification,
  likelihood determination, impact analysis, risk determination, and risk response
- CVSS-based risk scoring with environmental and temporal modifiers
- Risk posture scoring using deterministic formulas derived from finding severity counts
- Risk register construction with likelihood (1-5), impact (1-5), and composite risk_score

### Deterministic Risk Posture Score Formula
You calculate overall_risk_posture_score using this EXACT formula:
  score = max(5, min(95, 100 - (critical_count × 4) - (high_count × 2) - (medium_count × 1)))
This formula is injected into your prompt with pre-computed values. You MUST use
the pre-computed score — never recalculate or deviate from it.

### Risk Register Severity-to-Likelihood-Impact Mapping
| Severity | Likelihood | Impact | Risk Score |
|----------|------------|--------|------------|
| CRITICAL | 5          | 5      | 25         |
| HIGH     | 4          | 4      | 16         |
| MEDIUM   | 3          | 3      | 9          |
| LOW      | 2          | 2      | 4          |
| INFO     | 1          | 1      | 1          |

### Business Impact Framing
You present risk in four business dimensions:
1. Financial Exposure — regulatory fines, breach costs, ransomware demands
2. Regulatory & Compliance Penalty — GDPR (up to 4% global annual turnover),
   PCI DSS (card scheme fines), HIPAA (up to $1.9M per violation category)
3. Operational Disruption — system downtime, productivity loss, recovery costs
4. Reputational Damage — customer attrition, media coverage, board scrutiny

### FAIR Qualitative Tiers
When FAIR quantitative data is unavailable, use qualitative tiers:
- Tier 1 (Critical): >$10M probable annual loss exposure
- Tier 2 (High): $1M-$10M probable annual loss exposure
- Tier 3 (Medium): $100K-$1M probable annual loss exposure
- Tier 4 (Low): <$100K probable annual loss exposure

### Conduct
You write in a board-ready, third-person executive tone. Risk scores and metrics
are derived exclusively from the provided findings data using the deterministic
formulas above. You never invent risk scores or fabricate financial figures.
You present every risk entry with explicit likelihood and impact justification."""

    async def analyse_scan(
        self,
        findings: List[Dict],
        client_name: str,
    ) -> Dict[str, Any]:
        """Analyse findings and produce a structured risk assessment with risk register.

        Args:
            findings:    List of finding dicts from the scan pipeline.
            client_name: Client organisation name.

        Returns:
            Structured dict including a risk_register key (array) for the frontend table.
        """
        if not self._has_provider():
            result = self._fallback_analysis(findings)
            result["risk_register"] = map_to_risk_register_structured(findings)
            result["local_summary"] = _build_local_summary(findings)
            return result

        # ── Pre-compute deterministic metrics ──────────────────────────────────
        confidence, pct = self._compute_data_completeness(findings)
        sev_counts = _count_severities(findings)

        # Deterministic risk posture score
        posture_score = max(
            5,
            min(
                95,
                100
                - (sev_counts["critical"] * 4)
                - (sev_counts["high"] * 2)
                - (sev_counts["medium"] * 1),
            ),
        )
        posture_band = _score_to_band(posture_score)

        # Top 10 findings for detailed risk analysis
        top_findings = _get_top_findings(findings, limit=10)
        cves_with_cvss = [
            {"cve_id": f.get("cve_id"), "cvss_score": f.get("cvss_score"), "title": f.get("title", "")}
            for f in findings
            if f.get("cve_id")
        ][:15]

        # Pre-compute structured risk register (also returned for DB persistence)
        risk_register = map_to_risk_register_structured(findings)

        # ── Build prompts ──────────────────────────────────────────────────────
        system = (
            self.system_prompt()
            + "\n\n"
            + self.anti_hallucination_directive()
            + "\n\n"
            + self.consulting_packaging_directive()
        )

        user = f"""## Risk Management Assessment Input: {client_name}

### Dataset Overview
- **Client:** {client_name}
- **Total findings:** {len(findings)}
- **Data confidence:** {confidence} ({pct}% completeness)

### Severity Distribution
| Severity | Count | Weight | Contribution |
|----------|-------|--------|--------------|
| CRITICAL | {sev_counts['critical']} | ×4 | -{sev_counts['critical'] * 4} points |
| HIGH     | {sev_counts['high']} | ×2 | -{sev_counts['high'] * 2} points |
| MEDIUM   | {sev_counts['medium']} | ×1 | -{sev_counts['medium'] * 1} points |
| LOW      | {sev_counts['low']} | ×0 | 0 points |

### Pre-Computed Overall Risk Posture Score
Formula: max(5, min(95, 100 - (critical×4) - (high×2) - (medium×1)))
= max(5, min(95, 100 - {sev_counts['critical'] * 4} - {sev_counts['high'] * 2} - {sev_counts['medium'] * 1}))
= **{posture_score}** / 100 — Band: **{posture_band}**

Use this EXACT score in your output. Do not recalculate.

### Top 10 Findings for Risk Analysis
{json.dumps(top_findings, indent=2)}

### CVEs and CVSS Scores (cite only these)
{json.dumps(cves_with_cvss, indent=2) if cves_with_cvss else 'No CVE IDs present in findings.'}

### Instructions
Produce a full risk management assessment for {client_name}.

The `output` field must contain 400-800 words of markdown covering:
1. **Overall Risk Posture** — the score ({posture_score}/100, {posture_band}) with business context
2. **Top Risks** — 5-10 prioritised risks with FAIR-aligned business impact framing
3. **Systemic Weaknesses** — patterns across the findings (not individual CVEs)
4. **Immediate Mitigations** — 3-5 actions ordered by risk reduction impact
5. **Risk Treatment Recommendations** — for each severity band: accept/treat/transfer/avoid

The output MUST also include a "risk_register" key (array) — the frontend renders
this as a structured table. Each entry in risk_register must have:
  title, description, risk_level, likelihood (1-5), impact (1-5),
  risk_score (likelihood×impact), category, treatment

Finding IDs must use prefix RISK with sub-domains:
- RISK-RS-NNN: Risk Scoring
- RISK-RR-NNN: Risk Register
- RISK-RA-NNN: Risk Acceptance
- RISK-RP-NNN: Risk Posture

maturity_indicators sub_domains must include: risk_identification, risk_quantification,
risk_treatment, residual_risk_monitoring.

Use data_confidence="{confidence}" and data_completeness_pct={pct} exactly as given."""

        try:
            result = await self._call_llm(system, user)
        except Exception as exc:
            logger.error(f"RiskManagementAgent LLM error: {exc}")
            result = self._fallback_analysis(findings)

        # Ensure risk_register is always present and populated
        if not result.get("risk_register"):
            result["risk_register"] = risk_register

        result["local_summary"] = _build_local_summary(findings)
        result["posture_score"] = posture_score
        return result


# ── Module-level functions (called by router and orchestrator) ────────────────

def _infer_category(f: Dict) -> str:
    """Infer risk category from finding fields."""
    title = (f.get("title") or "").lower()
    cid = (f.get("control_id") or "").lower()
    desc = (f.get("description") or "").lower()

    if any(x in title or x in desc for x in ["cve", "vuln", "patch", "exploit", "unpatched"]):
        return "Vulnerability"
    if any(x in title or x in desc for x in ["auth", "mfa", "password", "access", "privilege", "permission"]):
        return "Access Control"
    if any(x in title or x in desc for x in ["encrypt", "tls", "ssl", "cert", "cryptograph"]):
        return "Cryptography"
    if any(x in title or x in desc for x in ["firewall", "network", "port", "exposure", "internet"]):
        return "Network Security"
    if any(x in title or x in desc for x in ["log", "monitor", "siem", "audit", "detect"]):
        return "Security Monitoring"
    if any(x in cid for x in ["ac", "ia", "ps"]):
        return "Access Control"
    if any(x in cid for x in ["si", "ra", "ca"]):
        return "Vulnerability Management"
    if any(x in cid for x in ["sc", "mp"]):
        return "Cryptography"
    return "Security Posture"


def map_to_risk_register_structured(findings: List[Dict]) -> List[Dict]:
    """Map findings list to structured risk register rows for DB persistence.

    Uses deterministic severity-to-likelihood-impact mapping. Called by the
    router independently of the LLM agent. Capped at 20 entries.
    """
    SEV_MAP: Dict[str, tuple] = {
        "critical": ("critical", 5, 5),
        "high": ("high", 4, 4),
        "medium": ("medium", 3, 3),
        "low": ("low", 2, 2),
        "info": ("low", 1, 1),
    }
    TREATMENT_MAP: Dict[str, str] = {
        "critical": "Treat immediately — emergency remediation within 24h",
        "high": "Treat — expedited remediation within 7 days",
        "medium": "Treat — standard remediation within 30 days",
        "low": "Monitor — scheduled remediation within 90 days",
        "info": "Accept — informational finding, review annually",
    }
    result = []
    for f in findings[:20]:
        sev = (f.get("severity") or "medium").lower()
        risk_level, likelihood, impact = SEV_MAP.get(sev, ("medium", 3, 3))
        treatment = TREATMENT_MAP.get(sev, "Treat")
        result.append({
            "title": (f.get("title") or "Unknown Risk")[:200],
            "description": (f.get("description") or "")[:500],
            "risk_level": risk_level,
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": likelihood * impact,
            "category": _infer_category(f),
            "treatment": treatment,
            "status": "open",
            "finding_ids": [],
        })
    return result


# ── Private helpers ────────────────────────────────────────────────────────────

def _count_severities(findings: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _score_to_band(score: int) -> str:
    if score >= 80:
        return "Low Risk"
    if score >= 60:
        return "Moderate Risk"
    if score >= 40:
        return "High Risk"
    if score >= 20:
        return "Critical Risk"
    return "Severe Risk"


def _get_top_findings(findings: List[Dict], limit: int = 10) -> List[Dict]:
    """Return top findings sorted by severity weight."""
    SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    sorted_f = sorted(
        findings,
        key=lambda x: (
            SEV_WEIGHT.get((x.get("severity") or "info").lower(), 0),
            x.get("cvss_score") or 0,
        ),
        reverse=True,
    )
    return [
        {
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "cve_id": f.get("cve_id"),
            "cvss_score": f.get("cvss_score"),
            "control_id": f.get("control_id"),
            "resource_id": f.get("resource_id"),
            "description": (f.get("description") or "")[:200],
        }
        for f in sorted_f[:limit]
    ]


def _build_local_summary(findings: List[Dict]) -> str:
    """Build a local rule-based summary string for backward compatibility."""
    counts = _count_severities(findings)
    total = len(findings)
    posture = max(
        5,
        min(95, 100 - counts["critical"] * 4 - counts["high"] * 2 - counts["medium"] * 1),
    )
    return (
        f"Total findings: {total} | Critical: {counts['critical']} | "
        f"High: {counts['high']} | Medium: {counts['medium']} | "
        f"Low: {counts['low']} | Risk Posture Score: {posture}/100"
    )
