"""Phase 8B follow-up — targeted gap-fill for coverage cells.

Given a ThreatModel and a list of missing (component, category) cells,
ask the LLM to either propose a threat or mark the cell with a rationale.
Cheaper than a full re-model — one focused prompt that only sees what's
needed to make the decision.

Output is merged into the model by the calling router endpoint.
"""
from __future__ import annotations
import json
import logging
from typing import Any, Dict, List, Tuple

from sqlalchemy.orm import Session

from api.models.models import ThreatModel
from services.threat_modeler import (
    METHODOLOGIES, DEFAULT_METHODOLOGY, THREAT_MODEL_MAX_TOKENS, _normalise,
)

# Cap how many gap cells we resolve per LLM call so the JSON response stays
# comfortably within the output-token budget (each cell yields a full threat
# or a decision). The router can be clicked again to fill the remainder.
_MAX_CELLS_PER_CALL = 40

logger = logging.getLogger(__name__)


_SYSTEM_PROMPT = """You are filling gaps in an existing STRIDE-style threat model. You are NOT producing a
full model — only resolving specific (component, category) cells that haven't been analysed.

For EACH cell I list below, return ONE entry. Either:

  A. Propose a real threat: state="threat", with the full threat shape
     (title, severity, likelihood, impact, evidence_refs, rationale,
     attack_narrative, blast_radius, owner_role, detection_status, etc.)

  B. Mark "considered" with a 1-sentence rationale explaining why no
     concrete threat applies given the component's role and constraints.

  C. Mark "not_applicable" with a 1-sentence rationale (e.g. "This component
     is read-only and has no privileged operations — Elevation of Privilege
     is structurally inapplicable").

Output STRICT JSON only — no prose, no markdown fences:

{
  "gaps": [
    {
      "component_id": "<from input>",
      "category": "<from input>",
      "state": "threat" | "considered" | "not_applicable",
      "rationale": "<one sentence — required for considered / not_applicable>",
      "threat": {
        "id": "TG<n>",
        "category": "<same as the cell category>",
        "asset_id": "<component_id>",
        "title": "...",
        "severity": "critical|high|medium|low",
        "likelihood": 1-10, "impact": 1-10,
        "evidence_refs": [{"kind":"asset|finding|cve|capec|attack","id":"...","label":"..."}],
        "capec_refs": [], "attack_techniques": [], "cwe_refs": [],
        "rationale": "...", "attack_narrative": "...",
        "blast_radius": ["<component_id>", ...],
        "owner_role": "security|appdev|platform|grc",
        "linked_finding_ids": [],
        "detection_status": "detected|gap|not_applicable",
        "detection_rule_refs": [],
        "status": "identified"
      }
    }
  ]
}

Rules:
- ONE entry per input cell — no extras, no skips.
- When state == "threat", `threat` is required and must be complete.
- When state != "threat", `threat` should be null. The `rationale` is mandatory.
- Threat IDs use the "TG" prefix to distinguish gap-fill threats from the
  original "T01" / "T02" sequence (e.g. "TG1", "TG2", …).
- Evidence_refs is preferred but optional when state="threat" (a threat
  without evidence is acceptable here, the consultant will see UNGROUNDED).
- Be concrete. "An attacker could potentially..." is rejected. State what
  the adversary DOES.
"""


async def fill_gaps(
    *,
    db: Session,
    tm: ThreatModel,
    missing_cells: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Run the gap-fill LLM call and parse the response.

    Returns (added_threats, updated_decisions) — the router merges these
    into the existing model."""
    if not missing_cells:
        return [], []

    # Bound the batch so the response JSON doesn't truncate at the output cap.
    missing_cells = missing_cells[:_MAX_CELLS_PER_CALL]

    methodology = (tm.methodology or DEFAULT_METHODOLOGY).lower()
    spec = METHODOLOGIES.get(methodology) or METHODOLOGIES[DEFAULT_METHODOLOGY]

    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        # Generous output budget — at the old 4096 cap a multi-cell response
        # truncated mid-JSON and failed to parse (502).
        llm = get_llm(temperature=0.2, max_tokens=THREAT_MODEL_MAX_TOKENS)
    except Exception as exc:
        raise RuntimeError(f"LLM unavailable for gap-fill: {exc}")

    # Build a focused context — just the components mentioned in the gaps
    # and a one-line summary of the model overall.
    components = tm.components_json or []
    comp_by_id = {str(c.get("id")): c for c in components}
    mentioned_comp_ids = {c.get("component_id") for c in missing_cells}
    relevant_components = [comp_by_id[cid] for cid in mentioned_comp_ids if cid in comp_by_id]

    lines = [
        f"## Methodology: {spec['label']}",
        f"## Model name: {tm.name or '(unnamed)'}",
        "",
        "## Relevant components (the ones with gaps):",
    ]
    for c in relevant_components:
        lines.append(
            f"- id={c.get('id')} name={c.get('name')} type={c.get('type')} "
            f"trust_zone={c.get('trust_zone')} criticality={c.get('criticality')}"
        )
    if tm.executive_summary:
        lines.append("")
        lines.append("## Existing model summary")
        lines.append(tm.executive_summary[:1000])
    lines.append("")
    lines.append("## Cells to resolve")
    for i, cell in enumerate(missing_cells, 1):
        lines.append(f"{i}. component_id={cell['component_id']}  category={cell['category']}")
    user_prompt = "\n".join(lines)

    try:
        result = await llm.ainvoke([
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=user_prompt),
        ])
    except Exception as exc:
        raise RuntimeError(f"gap-fill LLM call failed: {exc}")

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
        raise RuntimeError(f"gap-fill JSON parse failed: {exc}")

    gaps_raw = parsed.get("gaps") or []
    if not isinstance(gaps_raw, list):
        gaps_raw = []

    # Re-use the normaliser to clean up any new threats so they match the
    # canonical Phase 8 shape. We hand it a synthetic payload with ONLY
    # the new threats and the components they reference.
    new_threats_raw: List[Dict[str, Any]] = []
    cell_state_pairs: List[Dict[str, Any]] = []
    valid_cats = set(spec["categories"])

    existing_tg_max = 0
    for t in (tm.threats_json or []):
        tid = str(t.get("id") or "")
        if tid.startswith("TG"):
            try:
                n = int(tid[2:])
                existing_tg_max = max(existing_tg_max, n)
            except ValueError:
                pass

    for i, g in enumerate(gaps_raw):
        if not isinstance(g, dict):
            continue
        comp_id = str(g.get("component_id") or "")
        cat = str(g.get("category") or "").lower()
        if not comp_id or cat not in valid_cats:
            continue
        state = str(g.get("state") or "").lower()
        if state not in ("threat", "considered", "not_applicable"):
            state = "considered"
        rationale = str(g.get("rationale") or "")

        if state == "threat":
            t = g.get("threat") or {}
            if isinstance(t, dict) and (t.get("title") or t.get("rationale")):
                existing_tg_max += 1
                t.setdefault("id", f"TG{existing_tg_max}")
                t["asset_id"] = comp_id
                t["category"] = cat
                new_threats_raw.append(t)
                cell_state_pairs.append({
                    "component_id": comp_id, "category": cat,
                    "state": "threat", "threat_id": t["id"], "rationale": "",
                })
            else:
                # LLM said 'threat' but didn't actually provide one — demote.
                cell_state_pairs.append({
                    "component_id": comp_id, "category": cat,
                    "state": "considered", "threat_id": None,
                    "rationale": rationale or "Gap-fill LLM proposed a threat but did not provide details.",
                })
        else:
            cell_state_pairs.append({
                "component_id": comp_id, "category": cat,
                "state": state, "threat_id": None,
                "rationale": rationale or "(no rationale supplied)",
            })

    # Send new threats through the normaliser with a stub payload so they
    # get the same cleaning everything else does.
    stub = {
        "components": components,
        "data_flows": tm.data_flows_json or [],
        "threats": new_threats_raw,
        "mitigations": [],
        "coverage_decisions": [],
        "trust_boundaries": tm.trust_boundaries_json or [],
        "entry_points": tm.entry_points_json or [],
    }
    normalised = _normalise(stub, methodology)
    added_threats = normalised.get("threats") or []

    return added_threats, cell_state_pairs
