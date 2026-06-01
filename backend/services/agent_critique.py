"""Self-critique pass for catalog agent outputs.

Before persisting an agent's output, run a second LLM call asking the
model to review its own response for: factual errors, missing severity
calls, vague language, contradiction with the scan evidence, or
hallucinated control IDs / CVEs.

The critique step is opt-in (`AISettings.self_critique_enabled`) because
it doubles the per-agent token cost. When enabled, the original output,
the critique notes, and the revised output are all preserved on the
AgentRun row so the UI can show "self-reviewed · 3 corrections applied".

Failures here NEVER block the agent run — we fall back to the original
output. The whole point is to improve quality, not to introduce a new
failure mode.
"""
from __future__ import annotations
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


_CRITIQUE_SYSTEM = """You are a senior reviewer auditing a junior analyst's output.

You will be given (a) the original instruction with all evidence, and
(b) the analyst's proposed output. Your job: judge whether the output is
defensible, then either CONFIRM it or REVISE it. Apply this rubric:

  • Severity calls — does each finding have an explicit severity?
  • Evidence grounding — every claim should trace to the supplied context.
    Flag anything that looks invented (made-up CVEs, control IDs, or
    statistics).
  • Vagueness — phrases like "should be reviewed", "may be a concern",
    or "consider improving" are weak. Demand a concrete next step.
  • Contradiction — does the output contradict any line of the evidence?

Output STRICT JSON only — no prose, no fences:

{
  "decision": "confirm" | "revise",
  "issues": ["<short noun phrase>", ...],
  "revised_output": "<full revised markdown output if decision=revise, else empty string>"
}

If decision is "confirm", `issues` may still list minor nits that you chose
not to act on (so the UI can show "1 minor note reviewed"). If decision is
"revise", produce a complete replacement output — same format, same depth,
but corrected.
"""


def is_enabled(db) -> bool:
    """Cheap read of the tenant-wide toggle. Falls back to False if the
    table or column is missing (e.g. before the migration has run)."""
    try:
        from api.models.models import AISettings
        row = db.query(AISettings).first()
        return bool(row and getattr(row, "self_critique_enabled", False))
    except Exception as exc:
        logger.warning("self_critique_enabled lookup failed: %s", exc)
        return False


async def critique(
    *,
    llm,
    instruction: str,
    output: str,
) -> Dict[str, Any]:
    """Run the critique pass. Returns a dict with keys:

      - decision: 'confirm' | 'revise' | 'error'
      - issues: list[str]
      - revised_output: str  (empty if confirmed)
      - tokens: int (best-effort)

    Never raises — on any error returns decision='error' with the original
    output intact in caller-land (we just return revised_output='')."""
    if not output or not output.strip():
        return {"decision": "confirm", "issues": [], "revised_output": "", "tokens": 0}

    try:
        from langchain_core.messages import HumanMessage, SystemMessage
    except Exception as exc:
        logger.warning("langchain unavailable for critique: %s", exc)
        return {"decision": "error", "issues": [], "revised_output": "", "tokens": 0}

    user_body = (
        "## Original instruction (and evidence)\n\n"
        f"{instruction.strip()}\n\n"
        "## Analyst's proposed output\n\n"
        f"{output.strip()}\n\n"
        "Apply the rubric. Return JSON."
    )

    try:
        result = await llm.ainvoke([
            SystemMessage(content=_CRITIQUE_SYSTEM),
            HumanMessage(content=user_body),
        ])
    except Exception as exc:
        logger.warning("critique LLM call failed: %s", exc)
        return {"decision": "error", "issues": [], "revised_output": "", "tokens": 0}

    text = result.content if hasattr(result, "content") else str(result)
    if isinstance(text, list):
        text = "\n".join(str(p) for p in text)
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[:-3]
    try:
        start = text.find("{")
        end = text.rfind("}")
        parsed = json.loads(text[start:end + 1]) if start >= 0 and end > start else {}
    except Exception as exc:
        logger.warning("critique JSON parse failed: %s", exc)
        parsed = {}

    decision = str(parsed.get("decision") or "").lower()
    if decision not in ("confirm", "revise"):
        decision = "confirm"
    issues = parsed.get("issues") or []
    if not isinstance(issues, list):
        issues = [str(issues)]
    issues = [str(i)[:200] for i in issues][:12]
    revised = str(parsed.get("revised_output") or "")
    # Safety: if decision=revise but revised_output is empty/short, treat as confirm.
    if decision == "revise" and len(revised.strip()) < 40:
        decision = "confirm"
        revised = ""
    usage = getattr(result, "usage_metadata", None) or {}
    tokens = int(usage.get("total_tokens") or 0)
    return {
        "decision": decision,
        "issues": issues,
        "revised_output": revised,
        "tokens": tokens,
    }
