"""
NexGenCyberAI - Vulnerability Assessment Scan Agent
Senior vulnerability management consultant persona.
Analyses CVE/CVSS data against CIS Control 7, NIST CSF 2.0 ID.RA, and NIST 800-40 Rev4.
Produces priority-banded vulnerability queues, patch SLA dashboards, and remediation roadmaps.
"""
from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class VAScanAgent(BaseAgent):
    """Vulnerability Assessment Scan Agent.

    Analyses scan findings using CVSS v3.1, EPSS probability, CISA KEV context,
    and asset criticality to produce risk-prioritised vulnerability reports.
    """

    agent_name = "VAScanAgent"
    domain = "vulnerability assessment and CVE analysis"
    objective = (
        "Analyse vulnerability findings using CVSS v3.1, EPSS, and CISA KEV context. "
        "Produce risk-prioritised vulnerability queues and evidence-based remediation roadmaps."
    )

    def system_prompt(self) -> str:
        return """## Role: Senior Vulnerability Management Consultant

You are a senior vulnerability management consultant with 15 years of experience
designing and operating enterprise-scale security programs at Fortune 500 companies,
financial institutions, and critical infrastructure operators.

### Technical Expertise
You are an expert in:
- CVSS v3.1 scoring methodology (base, temporal, environmental vectors)
- EPSS (Exploit Prediction Scoring System) v3 — probability of exploitation within 30 days
- CISA Known Exploited Vulnerabilities (KEV) catalog — active exploitation in the wild
- Patch management lifecycle per NIST SP 800-40 Rev4
- Vulnerability program design per CIS Control 7 (Continuous Vulnerability Management)
- Asset criticality tiering and business-impact-weighted prioritisation
- NIST CSF 2.0 Identify (ID.RA) functions: ID.RA-01 through ID.RA-10

### Risk-Prioritised Remediation Framework
You apply a four-factor prioritisation model:
1. CVSS Base Score — inherent severity (0-10)
2. EPSS Probability — likelihood of exploitation within 30 days (0-100%)
3. KEV Presence — binary: is this actively exploited in the wild?
4. Asset Criticality — production/internet-facing assets receive a criticality multiplier

### Patch SLA Targets (NIST 800-40 Rev4 Alignment)
| Severity  | SLA Target | Change Category       |
|-----------|------------|-----------------------|
| CRITICAL  | 24 hours   | Emergency change      |
| HIGH      | 7 days     | Expedited change      |
| MEDIUM    | 30 days    | Standard change       |
| LOW       | 90 days    | Planned/normal change |

### Deliverables
You produce consultant-grade outputs:
- Executive vulnerability landscape summaries with business risk framing
- Prioritised vulnerability queues (top CVEs with CVSS, affected components, impact)
- Patch SLA compliance dashboards showing current counts vs. SLA targets
- Remediation roadmaps structured in 30/90/180/365-day bands
- Asset coverage assessments identifying unscanned or under-assessed assets

### Conduct
You write in a precise, third-person executive-report tone. You do not greet the reader,
offer further assistance, or use first-person voice. Every recommendation is grounded
exclusively in the findings data provided — you never fabricate CVE IDs, CVSS scores,
or tool names."""

    async def analyse_vulnerabilities(
        self,
        findings: List[Dict],
        client_name: str,
    ) -> Dict[str, Any]:
        """Analyse vulnerability findings and produce a structured assessment report.

        Args:
            findings:    List of finding dicts from the scan pipeline.
            client_name: Client organisation name for personalised output.

        Returns:
            Structured dict matching the BaseAgent output schema, augmented with
            priority_list and enriched_count for orchestrator compatibility.
        """
        if not self._has_provider():
            result = self._fallback_analysis(findings)
            result["priority_list"] = _build_priority_list(findings)
            result["enriched_count"] = len(findings)
            return result

        # ── Pre-compute deterministic metrics ──────────────────────────────────
        confidence, pct = self._compute_data_completeness(findings)
        sev_counts = _count_severities(findings)
        top_cves = _extract_top_cves(findings, limit=20)
        top_resources = _extract_top_resources(findings, limit=10)
        control_ids_breached = _extract_control_ids(findings)
        priority_list = _build_priority_list(findings)

        # ── Build prompts ──────────────────────────────────────────────────────
        system = (
            self.system_prompt()
            + "\n\n"
            + self.anti_hallucination_directive()
            + "\n\n"
            + self.consulting_packaging_directive()
        )

        user = f"""## Vulnerability Assessment Input: {client_name}

### Dataset Overview
- **Client:** {client_name}
- **Total findings:** {len(findings)}
- **Data confidence:** {confidence} ({pct}% completeness)

### Severity Distribution
| Severity | Count |
|----------|-------|
| CRITICAL | {sev_counts['critical']} |
| HIGH     | {sev_counts['high']} |
| MEDIUM   | {sev_counts['medium']} |
| LOW      | {sev_counts['low']} |
| INFO     | {sev_counts['info']} |

### Top CVEs Present in Findings (verbatim from data — cite only these)
{_format_cve_table(top_cves)}

### Top 10 Vulnerable Resource IDs
{_format_resource_list(top_resources)}

### Control IDs Breached
{', '.join(control_ids_breached[:30]) if control_ids_breached else 'None recorded in findings'}

### Patch SLA Targets
- CRITICAL: 24h emergency change — current count: {sev_counts['critical']}
- HIGH: 7d expedited change — current count: {sev_counts['high']}
- MEDIUM: 30d standard change — current count: {sev_counts['medium']}
- LOW: 90d planned change — current count: {sev_counts['low']}

### Instructions
Produce a full vulnerability management assessment for {client_name}.

The `output` field must contain 400-800 words of executive markdown covering:
1. **Vulnerability Landscape** — overall posture, severity distribution, trends
2. **Top Critical Vulnerabilities** — table of top CVEs (only those in the data above)
3. **Affected Asset Classes** — which resource types carry the most risk
4. **Patch SLA Compliance** — current state vs. 24h/7d/30d/90d targets
5. **Remediation Roadmap** — prioritised actions in 30/90/180d bands

Finding IDs must use prefix VUL with sub-domains:
- VUL-DI-NNN: Discovery & Inventory gaps
- VUL-PR-NNN: Prioritisation issues
- VUL-RM-NNN: Remediation Management failures
- VUL-RP-NNN: Reporting gaps

maturity_indicators sub_domains must include: asset_coverage, patch_velocity,
vulnerability_prioritisation, remediation_tracking.

Use data_confidence="{confidence}" and data_completeness_pct={pct} exactly as given."""

        try:
            result = await self._call_llm(system, user)
        except Exception as exc:
            logger.error(f"VAScanAgent LLM error: {exc}")
            result = self._fallback_analysis(findings)

        result["priority_list"] = priority_list
        result["enriched_count"] = len(findings)
        return result


# ── Module-level helpers ───────────────────────────────────────────────────────

def _count_severities(findings: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _extract_top_cves(findings: List[Dict], limit: int = 20) -> List[Dict]:
    """Extract unique CVEs with CVSS scores, sorted by score descending."""
    seen: Dict[str, Dict] = {}
    for f in findings:
        cve = f.get("cve_id")
        if cve and cve.startswith("CVE-"):
            existing = seen.get(cve)
            score = f.get("cvss_score") or 0
            if existing is None or score > (existing.get("cvss_score") or 0):
                seen[cve] = {
                    "cve_id": cve,
                    "cvss_score": score,
                    "severity": f.get("severity", ""),
                    "title": f.get("title", ""),
                }
    return sorted(seen.values(), key=lambda x: x.get("cvss_score") or 0, reverse=True)[:limit]


def _extract_top_resources(findings: List[Dict], limit: int = 10) -> List[str]:
    counter: Counter = Counter()
    for f in findings:
        rid = f.get("resource_id") or f.get("resource_type") or ""
        if rid:
            counter[rid] += 1
    return [r for r, _ in counter.most_common(limit)]


def _extract_control_ids(findings: List[Dict]) -> List[str]:
    ids = sorted({f.get("control_id") for f in findings if f.get("control_id")})
    return ids


def _format_cve_table(cves: List[Dict]) -> str:
    if not cves:
        return "No CVE IDs present in findings."
    lines = ["| CVE ID | CVSS | Severity | Title |", "|--------|------|----------|-------|"]
    for c in cves:
        score = f"{c['cvss_score']:.1f}" if c.get("cvss_score") else "N/A"
        title = (c.get("title") or "")[:60]
        lines.append(f"| {c['cve_id']} | {score} | {c.get('severity','').upper()} | {title} |")
    return "\n".join(lines)


def _format_resource_list(resources: List[str]) -> str:
    if not resources:
        return "No resource IDs recorded."
    return "\n".join(f"- {r}" for r in resources)


def _build_priority_list(findings: List[Dict]) -> str:
    """Build human-readable priority list sorted by CVSS score."""
    sorted_f = sorted(findings, key=lambda x: x.get("cvss_score") or 0, reverse=True)
    lines = []
    for f in sorted_f[:20]:
        score = f.get("cvss_score") or 0
        sev = (f.get("severity") or "").upper()
        title = (f.get("title") or "")[:80]
        cve = f.get("cve_id") or ""
        lines.append(f"CVSS {score:4.1f} | {sev:8s} | {title} | {cve}")
    return "\n".join(lines)
