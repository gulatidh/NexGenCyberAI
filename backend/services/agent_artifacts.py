"""Phase 7A — artifact-producing buddies.

Each catalog agent declares an `output_kind` that tells the runner what
shape its output should take. When != "prose", the runner appends a
strict-JSON-schema directive to the system prompt, parses the model's
response, and persists structured artifacts on
`AgentRun.output_data.artifacts[]` alongside the prose `summary`.

The artifacts can then be applied — converted into a concrete entity
(Risk row, Framework assessment evidence, KB runbook, finding triage
update) — with one click from the UI via
`POST /agents/catalog/runs/{id}/artifacts/{idx}/apply`.

This module owns:
  - The canonical schemas per kind.
  - The system-prompt suffix that nudges the LLM to emit them.
  - The parse-and-validate pipeline that lands them on the AgentRun.

The applier (which writes Risk / Framework / KB rows) lives in the
router, not here — keeps schema concerns separate from side effects.
"""
from __future__ import annotations
import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Kind registry ────────────────────────────────────────────────────────────


VALID_KINDS = {"prose", "risk_drafts", "jira_drafts", "control_mappings", "runbook", "finding_triage"}


# Per-kind JSON schema (described in prose; we don't validate against a
# real JSON Schema engine — the LLM produces approximate JSON which we
# coerce on parse).
_SCHEMA_PROSE = ""

_SCHEMA_RISK_DRAFTS = """{
  "summary": "<2-4 sentence executive overview tying the drafts to evidence>",
  "artifacts": [
    {
      "title": "<short risk title>",
      "severity": "<critical|high|medium|low>",
      "likelihood": <1-10>,
      "impact": <1-10>,
      "category": "<short category, e.g. Identity, Patching, Data Protection>",
      "rationale": "<2-3 sentences justifying severity grounded in evidence>",
      "control_refs": ["NIST-...", "CIS-..."],
      "owner_role": "<security|platform|appdev|grc>",
      "mitigation_plan": "<concrete remediation steps>"
    }
  ]
}"""

_SCHEMA_JIRA_DRAFTS = """{
  "summary": "<one paragraph context>",
  "artifacts": [
    {
      "project_key": "<JIRA project hint, e.g. SEC>",
      "issue_type": "<Bug|Task|Story>",
      "summary": "<single-line ticket title>",
      "priority": "<Highest|High|Medium|Low>",
      "labels": ["security", "..."],
      "description_md": "<markdown body — what, why, acceptance criteria>"
    }
  ]
}"""

_SCHEMA_CONTROL_MAPPINGS = """{
  "summary": "<which framework(s) this output addresses>",
  "artifacts": [
    {
      "framework": "<nist_csf|nist_800_53|iso_27001|cis_v8|...>",
      "control_id": "<framework control identifier>",
      "evidence": "<2-4 sentences citing the finding/asset/scan that supports this control>",
      "status": "<implemented|partially_implemented|not_implemented|not_applicable>",
      "confidence": "<high|medium|low>"
    }
  ]
}"""

_SCHEMA_RUNBOOK = """{
  "summary": "<what this runbook is for>",
  "artifacts": [
    {
      "title": "<runbook title>",
      "trigger": "<one-line condition that should trigger this runbook>",
      "audience": "<role that runs it, e.g. SOC analyst tier 1>",
      "steps": [
        {"order": 1, "action": "<imperative step>", "notes": "<optional caveats>"}
      ],
      "rollback_steps": ["<step 1>", "<step 2>"]
    }
  ]
}"""

_SCHEMA_FINDING_TRIAGE = """{
  "summary": "<one-paragraph triage logic>",
  "artifacts": [
    {
      "finding_id": "<id of an existing finding>",
      "recommended_status": "<open|in_progress|accepted|compensating_control|closed>",
      "recommended_owner_role": "<security|platform|appdev|grc>",
      "priority_score": <0.0-1.0>,
      "rationale": "<one sentence why>"
    }
  ]
}"""


KIND_SCHEMAS: Dict[str, str] = {
    "prose":            _SCHEMA_PROSE,
    "risk_drafts":      _SCHEMA_RISK_DRAFTS,
    "jira_drafts":      _SCHEMA_JIRA_DRAFTS,
    "control_mappings": _SCHEMA_CONTROL_MAPPINGS,
    "runbook":          _SCHEMA_RUNBOOK,
    "finding_triage":   _SCHEMA_FINDING_TRIAGE,
}


# Short human labels for UI badges
KIND_LABELS: Dict[str, str] = {
    "prose":            "Briefing",
    "risk_drafts":      "Risk drafts",
    "jira_drafts":      "Ticket drafts",
    "control_mappings": "Control mappings",
    "runbook":          "Runbook",
    "finding_triage":   "Finding triage",
}


# ── Prompt envelope ──────────────────────────────────────────────────────────


def prompt_suffix(kind: str, override_schema: Optional[str] = None) -> str:
    """Return a system-prompt suffix that nudges the LLM to emit the
    canonical JSON for this artifact kind. Empty string for 'prose'."""
    if kind == "prose" or kind not in KIND_SCHEMAS:
        return ""
    schema = override_schema or KIND_SCHEMAS[kind]
    return (
        "\n\n## Output format (STRICT)\n"
        "Return ONE JSON object — no prose outside JSON, no markdown fences:\n"
        f"{schema}\n\n"
        "Rules:\n"
        "- `summary` is markdown — that's what the user reads at the top of the card.\n"
        "- `artifacts` is the list of concrete deliverables a human can act on.\n"
        "- If you cannot ground an artifact in the supplied evidence, emit fewer "
        "artifacts. Quality over quantity — 1 well-grounded artifact beats 4 vague ones.\n"
        "- Use stable enum / category values; the platform validates and may drop bad rows.\n"
    )


# ── Parser ───────────────────────────────────────────────────────────────────


def parse_response(kind: str, raw_text: str) -> Dict[str, Any]:
    """Parse an LLM response into {summary, artifacts, errors}.

    Defensive: handles ```json fences, leading/trailing prose,
    malformed JSON (returns the raw text as summary with empty artifacts).
    """
    if kind == "prose" or not raw_text:
        return {"summary": raw_text or "", "artifacts": [], "errors": []}

    text = raw_text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[:-3]
    # Snip to the largest JSON object substring.
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("no JSON object detected")
        parsed = json.loads(text[start:end + 1])
    except Exception as exc:
        logger.warning("artifact JSON parse failed (kind=%s): %s", kind, exc)
        return {
            "summary": raw_text,
            "artifacts": [],
            "errors": [f"Couldn't parse structured output: {type(exc).__name__}. Showing raw prose."],
        }

    summary = str(parsed.get("summary") or "").strip()
    artifacts = parsed.get("artifacts") or []
    if not isinstance(artifacts, list):
        artifacts = []
    # Per-kind cleanup / coercion
    cleaned = [_clean_artifact(kind, a) for a in artifacts[:25]]
    cleaned = [a for a in cleaned if a is not None]
    return {"summary": summary or raw_text[:600], "artifacts": cleaned, "errors": []}


_SEV = {"critical", "high", "medium", "low"}
_OWNER_ROLES = {"security", "platform", "appdev", "grc"}
_STATUS = {"open", "in_progress", "accepted", "compensating_control", "closed"}
_PRIORITY = {"highest", "high", "medium", "low"}
_ASSESS_STATUS = {"implemented", "partially_implemented", "not_implemented", "not_applicable"}
_CONFIDENCE = {"high", "medium", "low"}


def _clip(v: Any, lo: int, hi: int, default: int) -> int:
    try:
        n = int(v)
        return max(lo, min(hi, n))
    except Exception:
        return default


def _str(v: Any, limit: int = 500) -> str:
    return ("" if v is None else str(v))[:limit]


def _clean_artifact(kind: str, a: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(a, dict):
        return None
    if kind == "risk_drafts":
        sev = _str(a.get("severity")).lower()
        if sev not in _SEV:
            sev = "medium"
        role = _str(a.get("owner_role")).lower()
        if role not in _OWNER_ROLES:
            role = "security"
        refs = a.get("control_refs") or []
        if not isinstance(refs, list):
            refs = [str(refs)]
        return {
            "title": _str(a.get("title"), 200) or "(untitled risk)",
            "severity": sev,
            "likelihood": _clip(a.get("likelihood"), 1, 10, 5),
            "impact": _clip(a.get("impact"), 1, 10, 5),
            "category": _str(a.get("category"), 80),
            "rationale": _str(a.get("rationale"), 2000),
            "control_refs": [_str(r, 64) for r in refs][:10],
            "owner_role": role,
            "mitigation_plan": _str(a.get("mitigation_plan"), 2000),
        }
    if kind == "jira_drafts":
        pri = _str(a.get("priority")).lower()
        if pri not in _PRIORITY:
            pri = "medium"
        labels = a.get("labels") or []
        if not isinstance(labels, list):
            labels = [str(labels)]
        return {
            "project_key": _str(a.get("project_key"), 32) or "SEC",
            "issue_type": _str(a.get("issue_type"), 32) or "Task",
            "summary": _str(a.get("summary"), 240) or "(no title)",
            "priority": pri.title(),
            "labels": [_str(l, 32) for l in labels][:12],
            "description_md": _str(a.get("description_md"), 6000),
        }
    if kind == "control_mappings":
        st = _str(a.get("status")).lower()
        if st not in _ASSESS_STATUS:
            st = "partially_implemented"
        conf = _str(a.get("confidence")).lower()
        if conf not in _CONFIDENCE:
            conf = "medium"
        return {
            "framework": _str(a.get("framework"), 64).lower(),
            "control_id": _str(a.get("control_id"), 96),
            "evidence": _str(a.get("evidence"), 2000),
            "status": st,
            "confidence": conf,
        }
    if kind == "runbook":
        steps_raw = a.get("steps") or []
        steps: List[Dict[str, Any]] = []
        if isinstance(steps_raw, list):
            for i, s in enumerate(steps_raw[:30], 1):
                if isinstance(s, dict):
                    steps.append({
                        "order": _clip(s.get("order"), 1, 999, i),
                        "action": _str(s.get("action"), 1000),
                        "notes": _str(s.get("notes"), 500),
                    })
                elif isinstance(s, str):
                    steps.append({"order": i, "action": _str(s, 1000), "notes": ""})
        rb_raw = a.get("rollback_steps") or []
        rb = [_str(s, 500) for s in rb_raw if isinstance(s, (str, int, float))][:15] if isinstance(rb_raw, list) else []
        return {
            "title": _str(a.get("title"), 200) or "(untitled runbook)",
            "trigger": _str(a.get("trigger"), 400),
            "audience": _str(a.get("audience"), 100),
            "steps": steps,
            "rollback_steps": rb,
        }
    if kind == "finding_triage":
        st = _str(a.get("recommended_status")).lower()
        if st not in _STATUS:
            st = "open"
        role = _str(a.get("recommended_owner_role")).lower()
        if role not in _OWNER_ROLES:
            role = "security"
        try:
            score = float(a.get("priority_score") or 0.5)
            score = max(0.0, min(1.0, score))
        except Exception:
            score = 0.5
        return {
            "finding_id": _str(a.get("finding_id"), 36),
            "recommended_status": st,
            "recommended_owner_role": role,
            "priority_score": round(score, 3),
            "rationale": _str(a.get("rationale"), 500),
        }
    return None
