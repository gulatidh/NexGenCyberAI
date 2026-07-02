"""
NexGenCyberAI - Remediation Agent
Senior security engineer specialising in vulnerability remediation orchestration.
Produces priority-banded remediation playbooks with SOAR automation guidance.
Aligned to NIST 800-40 Rev4 patch management and ITIL change management.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class RemediationAgent(BaseAgent):
    """Remediation Agent.

    Generates priority-banded remediation playbooks, patch SLA dashboards,
    SOAR automation opportunities, and exception criteria.
    """

    agent_name = "RemediationAgent"
    domain = "security remediation and playbook generation"
    objective = (
        "Generate priority-banded remediation playbooks aligned to NIST 800-40 Rev4. "
        "Identify SOAR automation opportunities and exception criteria."
    )

    def system_prompt(self) -> str:
        return """## Role: Senior Security Engineer — Vulnerability Remediation Orchestration

You are a senior security engineer with 14 years of experience designing and operating
vulnerability management and remediation orchestration programs at scale. You have led
patch management programs for cloud-native environments, hybrid enterprise infrastructure,
and OT/SCADA systems.

### Technical Expertise
You are an expert in:
- **NIST SP 800-40 Rev4** (Guide to Enterprise Patch and Vulnerability Management):
  Stage 1 — Discovery; Stage 2 — Reporting; Stage 3 — Prioritisation;
  Stage 4 — Remediation (deploy, verify, document)
- **ITIL change management**: Emergency Change, Expedited Change, Standard Change,
  Normal Change — each with distinct approval gates and rollback procedures
- **SOAR automation** platforms: ServiceNow SecOps, Palo Alto Cortex XSOAR,
  Splunk SOAR, Tines, Microsoft Sentinel Playbooks
- **Compensating controls** — when patching is not immediately feasible due to
  operational constraints, change freezes, or vendor dependencies
- **Exception management** — risk-accepted exceptions with time bounds, compensating
  control requirements, and re-assessment triggers
- **Remediation KPI frameworks**: Mean Time to Remediate (MTTR), Patch SLA compliance
  rate, Vulnerability Recurrence Rate, Remediation Velocity

### SLA Framework (NIST 800-40 Rev4 Aligned)
| Severity  | SLA Target | Change Category       | Approval Gate          |
|-----------|------------|-----------------------|------------------------|
| CRITICAL  | 24 hours   | Emergency change      | CISO verbal + CAB post |
| HIGH      | 7 days     | Expedited change      | CAB emergency session  |
| MEDIUM    | 30 days    | Standard change       | Weekly CAB             |
| LOW       | 90 days    | Normal/backlog        | Monthly CAB            |

### Playbook Band Labels (use EXACTLY these strings)
- "Quick Win (0-30d)"
- "Near Term (30-90d)"
- "Medium Term (90-180d)"
- "Strategic (180d+)"

### SOAR Automation Identification
For each finding category, identify automation opportunities:
- Auto-ticketing: CRITICAL/HIGH findings → automatic ServiceNow/Jira ticket creation
- Auto-routing: Route to asset owner based on resource_id/resource_type
- Auto-patching: OS patches → WSUS/SCCM/Ansible playbook trigger
- Auto-scanning: Post-patch rescan via the originating scanner connector
- Escalation automation: SLA breach alerts to CISO/management

### Exception Criteria Design
When patching is not immediately feasible:
- Document business justification (production freeze, vendor dependency, OT risk)
- Implement compensating controls (WAF rule, network segmentation, enhanced monitoring)
- Set time-bound exception window (max 90 days for HIGH, 30 days for CRITICAL)
- Define re-assessment trigger (vendor patch release, compensating control failure)

### Conduct
You write in a technical, action-oriented tone appropriate for security operations teams.
Every playbook step references technologies present in the findings data. You never
invent patch procedures for technologies not mentioned in the provided data.
You produce specific, executable steps — not generic advice."""

    async def generate_playbook(
        self,
        findings: List[Dict],
        client_name: str,
    ) -> Dict[str, Any]:
        """Generate priority-banded remediation playbooks for the provided findings.

        Args:
            findings:    List of finding dicts from the scan pipeline.
            client_name: Client organisation name.

        Returns:
            Structured dict with playbooks, patch_sla_dashboard, and automation guidance.
        """
        if not self._has_provider():
            result = self._fallback_analysis(findings)
            return result

        # ── Pre-compute deterministic metrics ──────────────────────────────────
        confidence, pct = self._compute_data_completeness(findings)
        sev_counts = _count_severities(findings)

        # Group findings by severity band
        bands: Dict[str, List[Dict]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }
        for f in findings:
            sev = (f.get("severity") or "low").lower()
            if sev in bands:
                bands[sev].append(f)
            else:
                bands["low"].append(f)

        # Build band summaries for prompt
        band_summaries = {}
        for band_name, band_findings in bands.items():
            band_summaries[band_name] = {
                "count": len(band_findings),
                "sample_findings": [
                    {
                        "title": f.get("title", ""),
                        "cve_id": f.get("cve_id"),
                        "cvss_score": f.get("cvss_score"),
                        "resource_id": f.get("resource_id", ""),
                        "control_id": f.get("control_id", ""),
                    }
                    for f in band_findings[:8]  # top 8 per band
                ],
            }

        # Unique resource types for technology context
        resource_types = sorted({
            f.get("resource_type") for f in findings if f.get("resource_type")
        })
        control_ids = sorted({f.get("control_id") for f in findings if f.get("control_id")})

        # ── Build prompts ──────────────────────────────────────────────────────
        system = (
            self.system_prompt()
            + "\n\n"
            + self.anti_hallucination_directive()
            + "\n\n"
            + self.consulting_packaging_directive()
        )

        user = f"""## Remediation Playbook Input: {client_name}

### Dataset Overview
- **Client:** {client_name}
- **Total findings:** {len(findings)}
- **Data confidence:** {confidence} ({pct}% completeness)

### Severity Distribution & SLA Dashboard
| Severity | Count | SLA Target | Change Category       |
|----------|-------|------------|-----------------------|
| CRITICAL | {sev_counts['critical']} | 24 hours | Emergency change |
| HIGH     | {sev_counts['high']} | 7 days   | Expedited change |
| MEDIUM   | {sev_counts['medium']} | 30 days  | Standard change  |
| LOW      | {sev_counts['low']} | 90 days  | Normal/backlog   |

### Findings by Band
{json.dumps(band_summaries, indent=2)}

### Resource Types Present (technologies to remediate)
{', '.join(resource_types) if resource_types else 'Not specified'}

### Control IDs Breached
{', '.join(control_ids[:25]) if control_ids else 'None recorded'}

### Instructions
Produce a prioritised remediation orchestration report for {client_name}.

The `output` field must contain 400-800 words of markdown covering:
1. **Remediation Program Overview** — total scope, SLA compliance risk, priority actions
2. **Band 1 — Quick Win (0-30d)** — emergency and high-priority remediations with specific steps
3. **Band 2 — Near Term (30-90d)** — medium-priority systematic remediation
4. **Band 3 — Medium Term (90-180d)** — architectural improvements and process fixes
5. **Band 4 — Strategic (180d+)** — program maturity and tooling investments
6. **SOAR Automation Opportunities** — which steps can be automated and how
7. **Exception Criteria** — when patching is not immediately feasible

In the recommendations array, use EXACTLY these band strings:
- "Quick Win (0-30d)"
- "Near Term (30-90d)"
- "Medium Term (90-180d)"
- "Strategic (180d+)"

Finding IDs must use prefix VRO with sub-domains:
- VRO-PBK-NNN: Playbooks
- VRO-SLA-NNN: SLA Tracking
- VRO-EXC-NNN: Exceptions

maturity_indicators sub_domains must include: patch_velocity, sla_compliance,
automation_coverage, exception_management.

Use data_confidence="{confidence}" and data_completeness_pct={pct} exactly as given."""

        try:
            result = await self._call_llm(system, user)
        except Exception as exc:
            logger.error(f"RemediationAgent LLM error: {exc}")
            result = self._fallback_analysis(findings)

        return result


# ── Module-level helpers ───────────────────────────────────────────────────────

def _count_severities(findings: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts
