"""
NexGenCyberAI - Threat Intelligence Agent
Senior threat intelligence analyst persona.
Maps findings to MITRE ATT&CK, assesses threat actor relevance, and identifies detection gaps.
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class ThreatIntelAgent(BaseAgent):
    """Threat Intelligence Agent.

    Correlates security findings with MITRE ATT&CK techniques, assesses threat
    actor profiles, identifies detection gaps, and produces Sigma rule stubs.
    """

    agent_name = "ThreatIntelAgent"
    domain = "threat intelligence and MITRE ATT&CK"
    objective = (
        "Correlate security findings with threat actor TTPs using MITRE ATT&CK. "
        "Identify detection gaps and produce actionable intelligence for the SOC."
    )

    def system_prompt(self) -> str:
        return """## Role: Senior Threat Intelligence Analyst & SOC Architect

You are a senior threat intelligence analyst with 12 years of experience supporting
Security Operations Centres at financial sector, government, and critical infrastructure
organisations. You also design CTI programs and detection engineering frameworks.

### Technical Expertise
You are an expert in:
- MITRE ATT&CK framework v15 — Tactics (14), Techniques (700+), Sub-techniques (400+),
  Procedures, and Data Sources
- Threat actor profiling using the Diamond Model (adversary, infrastructure, capability, victim)
- Pyramid of Pain — understanding which IOC types are most costly for adversaries to change
- CTI program design: strategic, operational, and tactical intelligence tiers
- Detection engineering: Sigma rules (YAML-format generic detection), YARA patterns,
  Suricata/Snort IDS signatures
- IOC lifecycle management and threat hunting hypothesis generation

### Verified Threat Actor Reference (cite only when evidence supports attribution)
The following threat groups are verified and documented in ATT&CK. You may reference them
ONLY when the findings data provides contextual evidence linking to their TTPs:
- APT38 (G0082) — North Korea-nexus, financial sector targeting, SWIFT fraud, T1059/T1071
- Lazarus Group (G0032) — North Korea-nexus, cryptocurrency theft, supply chain
- FIN7 (G0046) — financially motivated cybercrime, retail/hospitality, T1566/T1055
- Carbanak (G0008) — financially motivated cybercrime, banking sector
- APT29 / Cozy Bear (G0016) — Russia-nexus, government/diplomatic targeting, T1078/T1021
- ALPHV/BlackCat — ransomware-as-a-service, T1486, triple extortion
- Cl0p — ransomware-as-a-service, MOVEit-style mass exploitation
IMPORTANT: Never attribute findings to a specific threat actor without clear contextual
evidence in the provided data. Vague similarities are insufficient for attribution.

### MITRE ATT&CK Technique Mapping Methodology
You map findings to ATT&CK techniques using CONTEXTUAL ANALYSIS — not keyword matching.
A finding about "excessive admin privileges" maps to T1078 (Valid Accounts) because the
control failure enables that technique — not simply because the word matches. A missing
EDR maps to a Detection Gap across DE.AE-01 through DE.CM-09 because the absence of
telemetry means those techniques go undetected.

### Detection Engineering
For each identified technique, you produce Sigma rule stubs in correct YAML format:
```yaml
title: [Descriptive title]
status: experimental
logsource:
    category: [windows/linux/network/cloud]
    product: [windows/linux/azure/aws]
detection:
    selection:
        [field]: [value]
    condition: selection
falsepositives: [list]
level: [low/medium/high/critical]
```

### CTI Program Design
You design intelligence requirements using the Priority Intelligence Requirements (PIR)
framework. You identify intelligence gaps and recommend collection strategies.

### Conduct
You write in a precise, third-person analyst report tone. You ground all threat actor
attributions in evidence from the provided findings. You never speculate beyond what the
data supports. You distinguish clearly between observed TTPs (high confidence), inferred
TTPs (medium confidence), and possible TTPs (low confidence)."""

    async def enrich_findings(
        self,
        findings: List[Dict],
        client_name: str,
    ) -> Dict[str, Any]:
        """Enrich findings with threat intelligence and MITRE ATT&CK mapping.

        Args:
            findings:    List of finding dicts from the scan pipeline.
            client_name: Client organisation name.

        Returns:
            Structured dict with technique_mapping and enriched_findings added
            for backward compatibility with the orchestrator.
        """
        if not self._has_provider():
            result = self._fallback_analysis(findings)
            result["technique_mapping"] = {}
            result["enriched_findings"] = findings
            return result

        # ── Pre-compute deterministic metrics ──────────────────────────────────
        confidence, pct = self._compute_data_completeness(findings)
        sev_counts = _count_severities(findings)
        cves = [f.get("cve_id") for f in findings if f.get("cve_id")]
        unique_cves = sorted(set(cves))
        control_ids = sorted({f.get("control_id") for f in findings if f.get("control_id")})

        # Build finding titles/descriptions for TTP contextual analysis
        finding_contexts = []
        for f in findings[:50]:  # cap at 50 for prompt size
            finding_contexts.append({
                "title": f.get("title", ""),
                "description": (f.get("description") or "")[:200],
                "severity": f.get("severity", ""),
                "resource_type": f.get("resource_type", ""),
                "control_id": f.get("control_id", ""),
            })

        # ── Build prompts ──────────────────────────────────────────────────────
        system = (
            self.system_prompt()
            + "\n\n"
            + self.anti_hallucination_directive()
            + "\n\n"
            + self.consulting_packaging_directive()
        )

        user = f"""## Threat Intelligence Enrichment Input: {client_name}

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

### CVEs Present in Findings (only these may be cited)
{', '.join(unique_cves) if unique_cves else 'None'}

### Unique Control IDs Breached
{', '.join(control_ids[:30]) if control_ids else 'None'}

### Finding Contexts for TTP Mapping (top 50)
{json.dumps(finding_contexts, indent=2)}

### Instructions
Produce a threat intelligence assessment for {client_name}.

The `output` field must contain 400-800 words of markdown covering:
1. **Threat Landscape Assessment** — what attacker profiles are suggested by this control
   failure pattern (ground in actual findings data above)
2. **MITRE ATT&CK Technique Mapping** — map specific findings to specific techniques with
   confidence levels (observed/inferred/possible)
3. **Detection Gap Analysis** — which techniques have no detection coverage based on
   missing controls in the findings
4. **Sigma Rule Stubs** — at least 2 YAML Sigma rule stubs for the highest-priority
   detected techniques
5. **Priority Intelligence Requirements** — 3-5 PIRs the client SOC should pursue

Finding IDs must use prefix CTI with sub-domains:
- CTI-TL-NNN: Threat Landscape
- CTI-CP-NNN: Collection & Processing
- CTI-IR-NNN: Intelligence Requirements
- CTI-FD-NNN: Finished Intelligence
- SOC-DG-NNN: Detection Gaps

In each finding entry, add a "technique_id" and "tactic" field showing the ATT&CK mapping.

maturity_indicators sub_domains must include: threat_intelligence_program,
detection_coverage, incident_response_readiness, threat_hunting_capability.

Use data_confidence="{confidence}" and data_completeness_pct={pct} exactly as given."""

        try:
            result = await self._call_llm(system, user)
        except Exception as exc:
            logger.error(f"ThreatIntelAgent LLM error: {exc}")
            result = self._fallback_analysis(findings)

        # ── Backward compatibility additions for orchestrator ──────────────────
        # technique_mapping: simplified dict for orchestrator's use
        result["technique_mapping"] = {}
        # enriched_findings: pass through original findings (orchestrator reads this)
        result["enriched_findings"] = findings
        return result


# ── Module-level helpers ───────────────────────────────────────────────────────

def _count_severities(findings: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts
