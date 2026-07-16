"""
NexGenCyberAI - Base AI Agent
Provider-agnostic direct LLM call pattern using langchain_core messages.
All agents inherit from BaseAgent and use _call_llm() for structured JSON output.
"""
from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.messages import HumanMessage, SystemMessage

from core.ai_providers import get_llm, AIProvider
from core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class BaseAgent(ABC):
    """Abstract base for all Monitara AI agents.

    Subclasses must set:
        agent_name  – display name used in prompts and logs
        domain      – one-line domain description
        objective   – one-line objective statement

    Subclasses must implement:
        system_prompt() -> str   – domain-specific system prompt (200+ words)

    Core workflow for each agent method:
        1. Pre-compute deterministic metrics from findings (severity counts, etc.)
        2. Build system_prompt + anti_hallucination_directive + consulting_packaging_directive
        3. Build user_prompt with all pre-computed metrics injected
        4. Call _call_llm(system_prompt, user_prompt) → structured dict
        5. Augment result with any extra keys the orchestrator expects
        6. Return result
    """

    agent_name: str = "BaseAgent"
    domain: str = "cybersecurity"
    objective: str = "assist with cybersecurity tasks"

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        # Accept (and discard) legacy 'tools' kwarg so existing call sites don't break
        tools: Optional[List] = None,
    ):
        self._provider = provider
        self._model = model
        self.extra_context: Optional[str] = None  # injected by run_agent for custom frameworks
        self.resource_inventory: Optional[str] = None  # injected from scan.raw_context

    # ── Provider helpers ───────────────────────────────────────────────────────

    def _get_llm(self):
        return get_llm(provider=self._provider, model=self._model)

    def set_provider(self, provider: str, model: Optional[str] = None):
        """Switch AI provider at runtime."""
        self._provider = provider
        self._model = model

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    def system_prompt(self) -> str:
        """Domain-specific expert system prompt (200+ words). Must not include
        anti-hallucination rules or output format — those are added by the base
        class so they are consistent across all agents."""

    # ── Anti-hallucination & output directives ─────────────────────────────────

    def anti_hallucination_directive(self) -> str:
        return """## ANTI-HALLUCINATION RULES — MANDATORY COMPLIANCE

You MUST follow all 8 rules below without exception. Violating any rule produces
an unusable report and undermines client trust.

RULE 1 — NO INVENTED NUMBERS: Never fabricate counts, percentages, scores, or
financial figures. If a metric cannot be computed from the provided data, set it
to null. Do not estimate or round up to make the output look more complete.

RULE 2 — NO FABRICATED CVE IDs: You may only cite CVE identifiers that appear
verbatim in the findings input provided to you. Do not construct CVE IDs from
product names, version numbers, or general knowledge. If no CVEs are present in
the input, do not mention any CVE.

RULE 3 — VERIFIED FRAMEWORK CONTROL IDs: Use zero-padded NIST CSF 2.0 IDs
exactly: PR.AA-01 (not PR.AA-1), DE.CM-01 (not DE.CM-1), RS.RP-01 (not
RS.RP-1). CIS Controls format: "CIS.7.1" (Control 7, Safeguard 1). ISO 27001:
"A.8.1" format. Never invent control IDs.

RULE 4 — NO INVENTED TOOL NAMES: Reference only security tools, scanners, and
platforms that are explicitly mentioned in the findings or context provided. Do
not add tool names from general knowledge to make recommendations appear more
specific.

RULE 5 — ONE FINDING PER FINDING ID: Each finding ID (e.g., VUL-PR-001) maps to
exactly one vulnerability or control failure. Never consolidate multiple distinct
vulnerabilities into a single finding entry. Each entry must have a unique ID.

RULE 6 — PROGRAMMATIC DATA CONFIDENCE: Data confidence is determined by the
pre-computed values injected into your prompt — not by your subjective
assessment. Use the data_confidence and data_completeness_pct values exactly as
provided. Do not override them.

RULE 7 — NULL OVER GUESSING: Return null (JSON null) for any metric you cannot
derive directly from the provided findings data. Never guess, extrapolate, or
use domain knowledge to fill in missing values for client-specific metrics.

RULE 8 — SEVERITY ANCHORING: Use only these exact severity strings in all output:
CRITICAL, HIGH, MEDIUM, LOW, INFO. No other severity labels are permitted
(not "Moderate", not "Severe", not "Warning", not "Important")."""

    def consulting_packaging_directive(self) -> str:
        return f"""## MANDATORY OUTPUT FORMAT

You MUST return a single valid JSON object with ALL of the following top-level
keys. No text, no markdown fences, no commentary before or after the JSON.
Return ONLY the JSON object.

Required JSON structure:
{{
  "output": "## {self.agent_name} Analysis\\n\\n[Rich markdown narrative 400-800 words. Use ## and ### headers, bullet lists, and inline tables. Write in third-person executive-report tone. No greetings, no 'I will', no questions. Deliver real analysis of the specific findings provided.]",

  "executive_summary_structured": {{
    "posture_verdict": "[One sentence overall security posture assessment based on actual finding counts and severities]",
    "critical_findings_count": <integer from provided data>,
    "top_3_risks": ["[Risk 1 from actual findings]", "[Risk 2 from actual findings]", "[Risk 3 from actual findings]"],
    "quick_wins_90d": ["[Specific action 1]", "[Specific action 2]", "[Specific action 3]"]
  }},

  "findings": [
    {{
      "finding_id": "[PREFIX-SUBDOMAIN-001]",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "title": "[Specific finding title]",
      "description": "[Evidence-based description referencing actual findings data]",
      "framework_references": ["[e.g., NIST CSF 2.0 PR.AA-01]"],
      "remediation": "[Specific, actionable remediation step]"
    }}
  ],

  "recommendations": [
    {{
      "band": "Quick Win (0-30d)|Near Term (30-90d)|Medium Term (90-180d)|Strategic (180d+)",
      "priority": <integer 1-N>,
      "action": "[Specific action]",
      "effort": "Low|Medium|High",
      "impact": "Low|Medium|High"
    }}
  ],

  "maturity_indicators": {{
    "overall_tier": <integer 0-4>,
    "sub_domains": {{
      "[SUBDOMAIN_NAME]": {{
        "tier": <integer 0-4>,
        "evidence": "[Specific evidence from findings]"
      }}
    }}
  }},

  "data_confidence": "[low|medium|high — use pre-computed value from prompt]",
  "data_completeness_pct": <integer 0-100 — use pre-computed value from prompt>,
  "data_gaps": ["[Specific gap in available data]"]
}}

CRITICAL REMINDERS:
- The "output" value must be 400-800 words of real markdown analysis — not a template, not boilerplate
- Every finding_id must be unique within the array
- framework_references must use zero-padded IDs (PR.AA-01 not PR.AA-1)
- Return ONLY the JSON object — no surrounding text"""

    # ── Data completeness computation ──────────────────────────────────────────

    def _compute_data_completeness(self, findings: List[Dict]) -> Tuple[str, int]:
        """Compute (confidence, completeness_pct) from findings list.

        Formula:
            pct = min(100, finding_count × 2)
            +20 if any finding has a CVE ID
            +10 if any finding has a CVSS score
        Confidence:
            high   if pct >= 50 findings AND has CVEs
            medium if finding_count >= 10
            low    otherwise
        """
        count = len(findings)
        has_cves = any(f.get("cve_id") for f in findings)
        has_cvss = any(f.get("cvss_score") for f in findings)

        pct = min(100, count * 2)
        if has_cves:
            pct = min(100, pct + 20)
        if has_cvss:
            pct = min(100, pct + 10)

        if count >= 50 and has_cves:
            confidence = "high"
        elif count >= 10:
            confidence = "medium"
        else:
            confidence = "low"

        return confidence, pct

    # ── LLM call ──────────────────────────────────────────────────────────────

    async def _call_llm(self, system_prompt: str, user_prompt: str) -> Dict:
        """Invoke the LLM with system + user messages and parse JSON response.

        Strips code fences before JSON parsing. On any failure returns a minimal
        structured error dict that matches the expected output schema.
        """
        llm = self._get_llm()
        if self.resource_inventory:
            system_prompt = (
                system_prompt
                + f"\n\n## Resource Inventory\nThe following resources were discovered during the scan. "
                f"Use this to reason about assets that have no findings but may still be relevant to the security posture:\n\n"
                f"{self.resource_inventory}"
            )
        messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
        try:
            response = await llm.ainvoke(messages)
            raw = response.content if hasattr(response, "content") else str(response)
            # Strip code fences (```json ... ``` or ``` ... ```)
            raw = raw.strip()
            raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.MULTILINE)
            raw = re.sub(r'\s*```$', '', raw, flags=re.MULTILINE)
            raw = raw.strip()
            return json.loads(raw)
        except Exception as exc:
            logger.error(f"{self.agent_name} LLM call failed: {exc}")
            return {
                "output": f"## {self.agent_name} Analysis\n\nAgent encountered an error during analysis: {exc}\n\nThis report could not be generated. Please verify AI provider configuration and retry.",
                "error": str(exc),
                "data_confidence": "low",
                "data_completeness_pct": 0,
                "data_gaps": [str(exc)],
                "findings": [],
                "recommendations": [],
                "executive_summary_structured": {
                    "posture_verdict": "Analysis unavailable due to agent error.",
                    "critical_findings_count": 0,
                    "top_3_risks": [],
                    "quick_wins_90d": [],
                },
                "maturity_indicators": {"overall_tier": 0, "sub_domains": {}},
            }

    # ── Fallback (no LLM configured) ──────────────────────────────────────────

    def _fallback_analysis(self, findings: List[Dict]) -> Dict:
        """Minimal structured response when no AI provider is configured."""
        confidence, pct = self._compute_data_completeness(findings)
        count = len(findings)
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        return {
            "output": (
                f"## {self.agent_name} Analysis\n\n"
                f"**Note:** No AI provider is configured. Rule-based summary only.\n\n"
                f"### Findings Summary\n\n"
                f"- Total findings: {count}\n"
                f"- Critical: {sev_counts.get('critical', 0)}\n"
                f"- High: {sev_counts.get('high', 0)}\n"
                f"- Medium: {sev_counts.get('medium', 0)}\n"
                f"- Low: {sev_counts.get('low', 0)}\n\n"
                "Configure an AI provider (Azure OpenAI / OpenAI / Claude / Gemini / Bedrock) "
                "in the Connections → AI Settings page for full AI-powered analysis."
            ),
            "executive_summary_structured": {
                "posture_verdict": f"{count} findings identified. AI provider required for detailed assessment.",
                "critical_findings_count": sev_counts.get("critical", 0),
                "top_3_risks": [],
                "quick_wins_90d": [],
            },
            "findings": [],
            "recommendations": [],
            "maturity_indicators": {"overall_tier": 0, "sub_domains": {}},
            "data_confidence": confidence,
            "data_completeness_pct": pct,
            "data_gaps": ["AI provider not configured — LLM analysis unavailable"],
            "fallback": True,
            "provider": "none",
        }

    # ── Provider availability check ────────────────────────────────────────────

    def _has_provider(self) -> bool:
        return any([
            settings.AZURE_OPENAI_API_KEY,
            settings.OPENAI_API_KEY,
            settings.ANTHROPIC_API_KEY,
            settings.GOOGLE_API_KEY,
            settings.AWS_BEDROCK_REGION,
            settings.CUSTOM_OPENAI_BASE_URL,
        ])
