"""STRIDE-style threat model generator.

Pulls scope context (asset inventory + recent findings + connector
topology + framework controls + threat-intel signals) for a client or
project or single asset, calls an LLM with a strict JSON schema, and
persists a normalised threat model.

Output schema is enforced by `_normalise()` — even if the model
hallucinates extra fields or omits required ones we land at the same
shape every time so the frontend can render deterministically.

See `api/models/models.py::ThreatModel` for the storage shape.
"""
from __future__ import annotations
import asyncio
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from api.models.models import (
    Asset, Client, Connector, Finding, Project, Scan, ThreatLibrary, ThreatModel,
)

logger = logging.getLogger(__name__)


# ── Fixed schema fields (normaliser enforces these) ─────────────────────────


_COMPONENT_FIELDS = ("id", "name", "type", "trust_zone", "criticality", "notes")
_DATA_FLOW_FIELDS = ("from", "to", "protocol", "data", "encrypted", "notes")
# Phase 8 — expanded threat shape. Required: id, category, asset_id, title,
# severity, evidence_refs, rationale. Strongly encouraged: capec/attack/cwe
# refs, attack_narrative, blast_radius, owner_role, detection_status.
_THREAT_FIELDS = (
    "id", "category", "asset_id", "title", "severity",
    "evidence", "evidence_refs", "capec_refs", "attack_techniques", "cwe_refs",
    "rationale", "attack_narrative", "blast_radius", "owner_role",
    "likelihood", "impact", "priority_score",
    "status", "decision_notes", "decided_by", "decided_at",
    "residual_severity", "residual_rationale",
    "linked_finding_ids",
    "detection_status", "detection_rule_refs",
)
# Phase 8 — mitigation shape gets control_refs (multi-framework), required
# implementation_detail, and an evidence_link for "actually applied".
_MITIGATION_FIELDS = (
    "id", "threat_id", "action", "implementation_detail",
    "control_id", "control_refs", "status", "owner_role",
    "evidence_link",
)
_TRUST_BOUNDARY_FIELDS = ("id", "name", "from_zone", "to_zone", "description", "crossed_by_flow_ids")
_ENTRY_POINT_FIELDS = ("id", "kind", "name", "component_id", "exposure", "auth_required")

# Per-methodology valid categories. `category` on each threat must be one of
# these values for the picked methodology — if the LLM emits anything else
# we coerce to the methodology's most generic bucket.
METHODOLOGIES: Dict[str, Dict[str, Any]] = {
    "stride": {
        "label": "STRIDE",
        "description": "Microsoft STRIDE — Spoofing / Tampering / Repudiation / Information Disclosure / DoS / Elevation of Privilege. Best for application + system architecture.",
        "categories": [
            "spoofing", "tampering", "repudiation",
            "information_disclosure", "denial_of_service", "elevation_of_privilege",
        ],
        "default_category": "tampering",
    },
    "pasta": {
        "label": "PASTA",
        "description": "Process for Attack Simulation and Threat Analysis — 7 stages, business-objective-driven.",
        "categories": [
            "stage_1_objectives", "stage_2_technical_scope", "stage_3_decomposition",
            "stage_4_threat_analysis", "stage_5_vulnerability_analysis",
            "stage_6_attack_modeling", "stage_7_risk_impact",
        ],
        "default_category": "stage_4_threat_analysis",
    },
    "linddun": {
        "label": "LINDDUN",
        "description": "Privacy-focused — Linkability / Identifiability / Non-repudiation / Detectability / Disclosure / Unawareness / Non-compliance.",
        "categories": [
            "linkability", "identifiability", "non_repudiation", "detectability",
            "disclosure_of_information", "unawareness", "non_compliance",
        ],
        "default_category": "disclosure_of_information",
    },
    "mitre_attack": {
        "label": "MITRE ATT&CK",
        "description": "Adversary tactics — Initial Access / Execution / Persistence / Privilege Escalation / Defense Evasion / Credential Access / Discovery / Lateral Movement / Collection / C2 / Exfiltration / Impact.",
        "categories": [
            "initial_access", "execution", "persistence", "privilege_escalation",
            "defense_evasion", "credential_access", "discovery", "lateral_movement",
            "collection", "command_and_control", "exfiltration", "impact",
        ],
        "default_category": "initial_access",
    },
    "kill_chain": {
        "label": "Lockheed Martin Kill Chain",
        "description": "7 phases of an intrusion — Recon / Weaponization / Delivery / Exploitation / Installation / C2 / Actions on Objectives.",
        "categories": [
            "reconnaissance", "weaponization", "delivery", "exploitation",
            "installation", "command_and_control", "actions_on_objectives",
        ],
        "default_category": "exploitation",
    },
}
DEFAULT_METHODOLOGY = "stride"

# Hard ceiling on a single threat-model LLM call. A stalled provider socket
# would otherwise leave the row wedged in 'generating' indefinitely.
LLM_TIMEOUT_SECONDS = 180

_SEV = {"critical", "high", "medium", "low", "info"}
_STATUS = {"open", "in_progress", "accepted", "compensating_control", "closed"}


def methodology_catalog() -> List[Dict[str, Any]]:
    """Public list of methodologies for the frontend picker."""
    return [
        {"id": k, "label": v["label"], "description": v["description"],
         "categories": v["categories"]}
        for k, v in METHODOLOGIES.items()
    ]


# ── Scope collection ─────────────────────────────────────────────────────────


def _collect_scope(
    db: Session,
    client_id: str,
    scope_type: str,
    scope_id: Optional[str],
) -> Dict[str, Any]:
    """Build the context dict that gets injected into the LLM prompt."""
    client = db.query(Client).filter(Client.id == client_id).first()
    client_name = client.name if client else "Unknown Client"

    # ── Assets in scope ────
    assets_q = db.query(Asset).filter(Asset.client_id == client_id)
    if scope_type == "project" and scope_id:
        assets_q = assets_q.filter(Asset.project_id == scope_id)
    elif scope_type == "asset" and scope_id:
        assets_q = assets_q.filter(Asset.id == scope_id)
    assets = assets_q.limit(120).all()
    asset_rows = []
    for a in assets:
        # Pull every signal we can about an asset so the LLM uses real names,
        # types, and provider hints in the diagram instead of inventing
        # generic labels like "API1" / "Web Service".
        tags = getattr(a, "tags", None) or {}
        provider = tags.get("provider") if isinstance(tags, dict) else None
        asset_rows.append({
            "id": a.id,
            "name": a.name or a.external_id or a.id,
            "type": a.asset_type or "unknown",
            "external_id": a.external_id,
            "provider": provider,
            "criticality": getattr(a, "criticality", None) or "medium",
        })

    # ── Recent findings (last 50, severity-ordered) ────
    findings_q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id)
        .order_by(Finding.cvss_score.desc(), Finding.created_at.desc())
        .limit(50)
    )
    findings = findings_q.all()
    finding_rows = []
    sev_counts: Counter = Counter()
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_counts[sev] += 1
        finding_rows.append({
            "id": f.id,
            "title": (f.title or "")[:160],
            "severity": sev,
            "resource": f.resource_id or "",
            "cve": f.cve_id or "",
            "cvss": float(f.cvss_score) if f.cvss_score else None,
            "control": f.control_id or "",
        })

    # ── Connector topology ────
    connectors = (
        db.query(Connector)
        .filter(Connector.client_id == client_id)
        .all()
    )
    connector_types = sorted({
        (c.connector_type.value if hasattr(c.connector_type, "value") else str(c.connector_type))
        for c in connectors
    })

    return {
        "client_name": client_name,
        "scope_type": scope_type,
        "scope_id": scope_id,
        "asset_count": len(asset_rows),
        "assets": asset_rows,
        "finding_count": len(finding_rows),
        "findings_severity_counts": dict(sev_counts),
        "findings": finding_rows,
        "connector_types": connector_types,
    }


# ── Prompt building ──────────────────────────────────────────────────────────


_SYSTEM_PROMPT_TMPL = """You are a senior cybersecurity threat modeler producing a CONSULTANT-GRADE deliverable.
You apply the {label} methodology rigorously. {description}

Output STRICT JSON only — no prose, no markdown fences, no commentary outside the JSON object. The schema:

{{
  "executive_summary": "<2-4 sentence CISO-level overview>",
  "components": [
    {{ "id": "<short-slug>", "name": "<asset name>",
      "type": "<vm|storage|identity|repo|endpoint|database|api|queue|secret-store|other>",
      "trust_zone": "<public|dmz|private|data-tier|management>",
      "criticality": "<critical|high|medium|low>",
      "notes": "<one-line>" }}
  ],
  "data_flows": [
    {{ "from": "<component id>", "to": "<component id>",
      "protocol": "<https|sql|ssh|smb|grpc|amqp|other>",
      "data": "<credentials|pii|financial|telemetry|config|other>",
      "encrypted": <true|false>, "notes": "<one-line>" }}
  ],
  "trust_boundaries": [
    {{ "id": "tb1", "name": "Internet → DMZ",
      "from_zone": "public", "to_zone": "dmz",
      "description": "<one-line>", "crossed_by_flow_ids": ["f1","f2"] }}
  ],
  "entry_points": [
    {{ "id": "ep1", "kind": "http|websocket|api|cli|email|file_upload|webhook|other",
      "name": "/api/v1/login", "component_id": "<id>",
      "exposure": "internet|intranet|partner|internal",
      "auth_required": <true|false> }}
  ],
  "threats": [
    {{ "id": "T01",
      "category": "<one of: {categories_csv}>",
      "asset_id": "<component id this threat targets>",
      "title": "<short threat statement>",
      "severity": "<critical|high|medium|low>",
      "likelihood": <1-5>,
      "impact": <1-5>,
      "evidence_refs": [
        {{ "kind": "asset|finding|cve|capec|attack", "id": "<id>", "label": "<short>" }}
      ],
      "capec_refs": ["CAPEC-NN"], "attack_techniques": ["T1234"], "cwe_refs": ["CWE-79"],
      "rationale": "<2-3 sentences justifying severity grounded in evidence>",
      "attack_narrative": "<2-4 sentences: how an adversary would actually execute this — concrete steps, not abstract>",
      "blast_radius": ["<component id reachable if this is exploited>", "..."],
      "owner_role": "<security|appdev|platform|grc>",
      "linked_finding_ids": ["<finding id from the supplied finding list>", "..."],
      "detection_status": "detected|gap|not_applicable",
      "detection_rule_refs": [
        {{ "platform": "sentinel|splunk|elastic|chronicle|generic", "rule_id": "<id or name>" }}
      ],
      "status": "identified",
      "residual_severity": null,
      "residual_rationale": null
    }}
  ],
  "mitigations": [
    {{ "id": "M01", "threat_id": "T01",
      "action": "<concrete remediation step>",
      "implementation_detail": "<3-6 sentences: exactly what to configure / code / deploy. Not 'review your IAM policies' — 'enable Conditional Access policy requiring MFA for any sign-in from outside the corporate IP range, scoped to the Finance group'>",
      "control_refs": [
        {{ "framework": "nist_800_53|nist_csf|owasp_asvs|owasp_top10|cis_v8|iso_27001", "control_id": "AC-2" }}
      ],
      "status": "open",
      "owner_role": "<security|appdev|platform|grc>",
      "evidence_link": null
    }}
  ],
  "coverage_decisions": [
    {{ "component_id": "<id>", "category": "<stride/methodology category>",
      "state": "threat|considered|not_applicable",
      "threat_id": "<T0N if state=threat, else null>",
      "rationale": "<required when state != threat — one sentence explaining why no threat>" }}
  ],
  "dfd_mermaid": "flowchart TD\\n  ..."
}}

CRITICAL rules (these are gates, not preferences):

1. EVIDENCE — every threat MUST have at least one evidence_refs entry. Acceptable kinds:
   - asset: cite an asset by id from the supplied scope
   - finding: cite a finding_id from the supplied finding list
   - cve: cite a CVE-YYYY-NNNN if a finding references one
   - capec: cite a CAPEC-NN from the supplied threat library
   - attack: cite an ATT&CK technique ID (T1234) from the supplied threat library
   Threats without evidence_refs will be flagged 'ungrounded' and demoted on screen.

2. COMPLETENESS — components, data_flows, trust_boundaries, AND entry_points are ALL required. Do not
   omit trust_boundaries or entry_points. An entry point is anywhere data crosses INTO the system from
   an external actor (HTTP endpoints, file uploads, webhooks, message queues consumed from outside).

3. TIERED STRIDE COVERAGE — produce coverage_decisions covering:
   - Critical + High criticality components: ALL 6 STRIDE categories (or your methodology's full set)
   - Medium criticality components: only categories that plausibly apply (omit n/a with rationale)
   - Low criticality components: only categories with concrete attack surface
   Every (component, category) pair in this matrix MUST appear as a coverage_decisions entry — either
   pointing to a threat (state=threat with threat_id) or carrying a one-sentence rationale (state=considered
   or state=not_applicable). Empty coverage is a defect.

4. ATTACK NARRATIVE — for every threat, attack_narrative must read like an after-action report a SOC analyst
   would write. Concrete adversary, concrete steps, concrete data. Avoid 'an attacker could potentially' —
   say what they DO.

5. BLAST RADIUS — list the component ids the adversary reaches on success. Walk the data_flows from the
   compromised component; include any node connected by an unencrypted or credentials-bearing flow.

6. MITIGATIONS — every threat has at least one mitigation. implementation_detail is REQUIRED and must be
   specific enough to action without further analysis. control_refs MUST cite at least one of:
   nist_800_53 / nist_csf / owasp_asvs / owasp_top10 / cis_v8 / iso_27001.

7. DETECTION COVERAGE — for each threat, detection_status defaults to 'gap' unless you can name a
   specific generic detection family that would catch it (Microsoft Sentinel analytic rule, Splunk ES
   correlation search, etc.). When detection_status='detected', include detection_rule_refs.

8. DFD — dfd_mermaid is valid Mermaid `flowchart TD`. Group nodes by trust zone via `subgraph` blocks
   with the trust boundary names as labels. Each node MUST use the component's real `name` (verbatim
   from asset inventory when supplied) and include a `<br/><small>type</small>` sub-label so the
   diagram reads as a real architecture, not a generic abstract topology. Example node:
       order_db["payment-cosmosdb-prod<br/><small>database</small>"]
   Subgraph labels should be human-readable zone names, e.g.:
       subgraph DMZ["DMZ — public-facing"]

9. NO HALLUCINATED IDs — CAPEC, ATT&CK, CWE, and finding references must exist in the supplied lists.
   If you can't ground a threat in supplied evidence, leave its refs empty rather than inventing them.

10. PRIORITY — likelihood and impact are 1-5 integers. Severity tier is your overall call. The platform
    computes priority_score = severity_weight × likelihood × impact × asset_criticality_weight.

11. Use category values ONLY from this set for {label}: {categories_csv}.

12. Third-person, executive tone. No greetings, no questions, no 'I can also', no apologies.
"""


def _build_system_prompt(methodology: str) -> str:
    spec = METHODOLOGIES.get(methodology) or METHODOLOGIES[DEFAULT_METHODOLOGY]
    return _SYSTEM_PROMPT_TMPL.format(
        label=spec["label"],
        description=spec["description"],
        categories_csv="|".join(spec["categories"]),
    )


def _library_sample(db: Session, methodology: str, limit: int = 25) -> List[Dict[str, Any]]:
    """Pull up to `limit` library entries that the LLM should cite from.
    Strategy per methodology:

      - mitre_attack: source='attack', sampled across tactics
      - stride / pasta / linddun / kill_chain: source='capec' first,
        falling back to 'attack' if CAPEC isn't synced yet

    Returns a list of dicts {source_id, name, category, description (short)}.
    Empty list when no library data exists yet — generator works fine
    without it (just won't be grounded in real catalog IDs)."""
    try:
        if methodology == "mitre_attack":
            rows = (
                db.query(ThreatLibrary)
                .filter(ThreatLibrary.source == "attack")
                .order_by(ThreatLibrary.category, ThreatLibrary.source_id)
                .limit(limit * 3)
                .all()
            )
        else:
            rows = (
                db.query(ThreatLibrary)
                .filter(ThreatLibrary.source == "capec")
                .order_by(ThreatLibrary.source_id)
                .limit(limit * 2)
                .all()
            )
            if not rows:
                rows = (
                    db.query(ThreatLibrary)
                    .filter(ThreatLibrary.source == "attack")
                    .limit(limit * 2)
                    .all()
                )
    except Exception:
        return []

    # Diversify by category — pick at most N per bucket to avoid the
    # prompt being dominated by one tactic.
    per_cat: Dict[str, int] = {}
    out: List[Dict[str, Any]] = []
    for r in rows:
        cat = r.category or "uncategorised"
        per_cat[cat] = per_cat.get(cat, 0) + 1
        if per_cat[cat] > 4:
            continue
        out.append({
            "source_id": r.source_id,
            "name": (r.name or "")[:160],
            "category": cat,
            "summary": (r.description or "")[:200].replace("\n", " "),
        })
        if len(out) >= limit:
            break
    return out


def _build_user_prompt(scope: Dict[str, Any], framework: Optional[str], methodology: str,
                       library: Optional[List[Dict[str, Any]]] = None,
                       preset_components: Optional[List[Dict[str, Any]]] = None,
                       preset_data_flows: Optional[List[Dict[str, Any]]] = None) -> str:
    spec = METHODOLOGIES.get(methodology) or METHODOLOGIES[DEFAULT_METHODOLOGY]
    parts: List[str] = [
        "## Scope",
        f"Client: {scope['client_name']}",
        f"Scope type: {scope['scope_type']}" + (f" (id={scope['scope_id']})" if scope.get("scope_id") else ""),
        f"Connectors in play: {', '.join(scope['connector_types']) or 'none'}",
        f"Framework target: {framework or 'NIST CSF (default)'}",
        f"Methodology: {spec['label']}",
    ]

    # When the model was created from an uploaded diagram, the components +
    # data flows are already extracted. Treat them as authoritative
    # architecture and instruct the LLM to reuse the exact IDs so the
    # resulting DFD stays consistent with what the user reviewed.
    if preset_components:
        parts.append("")
        parts.append("## Authoritative architecture (from uploaded diagram — DO NOT modify or invent components)")
        parts.append(
            "These components and data flows were extracted from the customer's own architecture "
            "diagram and reviewed by them. Use the IDs exactly as given when emitting components, "
            "data_flows, and threats. Do not introduce new components; only the listed ones are in scope."
        )
        parts.append("### Components")
        for c in preset_components[:60]:
            parts.append(
                f"- id={c.get('id')}  name={c.get('name')}  type={c.get('type')}  "
                f"trust_zone={c.get('trust_zone')}  criticality={c.get('criticality')}"
            )
        if preset_data_flows:
            parts.append("### Data flows")
            for f in preset_data_flows[:60]:
                parts.append(
                    f"- {f.get('from')} → {f.get('to')}  protocol={f.get('protocol')}  "
                    f"data={f.get('data')}  encrypted={f.get('encrypted')}"
                )

    parts.append("")
    if scope["assets"]:
        parts.append(f"## Asset inventory — {len(scope['assets'])} discovered assets in scope. USE THESE EXACT NAMES.")
        parts.append("When you emit a component, set `name` to the asset's `name` verbatim and `id` to the asset's `id`. "
                     "Do NOT invent generic labels like 'API Gateway' or 'Web Service' when a real asset matches.")
        for a in scope["assets"][:60]:
            prov = f" provider={a.get('provider')}" if a.get('provider') else ""
            parts.append(f"- asset_id={a['id']}  name=\"{a['name']}\"  type={a['type']}  criticality={a['criticality']}{prov}")
    else:
        parts.append("## Asset inventory")
        parts.append("- (no assets discovered for this scope — model from architecture only, use descriptive names like 'Customer-facing API' not 'API1')")

    parts.append("")
    parts.append(f"## Finding signals — {scope['finding_count']} total: {scope['findings_severity_counts']}")
    parts.append("Cite finding IDs in `linked_finding_ids` and `evidence_refs` when a threat traces back to one.")
    for f in scope["findings"][:25]:
        parts.append(f"- finding_id={f['id']} [{f['severity']}] {f['title']} on `{f['resource'] or 'n/a'}` "
                     f"(CVE={f['cve'] or '—'}, CVSS={f['cvss'] or '—'}, control={f['control'] or '—'})")
    if not scope["findings"]:
        parts.append("- (no findings yet — model purely from architecture)")

    if library:
        parts.append("")
        parts.append(
            f"## Threat library — cite from THIS list only (CAPEC / ATT&CK refs MUST be real IDs from below)"
        )
        for entry in library:
            parts.append(f"- {entry['source_id']} ({entry['category'] or 'misc'}): {entry['name']} — {entry['summary']}")
        parts.append("")
        parts.append("If a threat doesn't map to any entry above, leave its capec_refs / attack_techniques arrays empty rather than inventing IDs.")

    parts.append("")
    parts.append(f"Produce the {spec['label']} threat model now. STRICT JSON only.")
    return "\n".join(parts)


# ── Schema normaliser ────────────────────────────────────────────────────────


def _str(x: Any, default: str = "") -> str:
    if x is None:
        return default
    return str(x)


def _pick_fields(obj: Any, keys) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        return {k: "" for k in keys}
    return {k: obj.get(k, "" if k != "encrypted" else False) for k in keys}


_VALID_THREAT_STATUS = {"identified", "mitigated", "accepted", "transferred", "compensated", "not_applicable"}
_VALID_OWNER_ROLE = {"security", "appdev", "platform", "grc"}
_VALID_DETECTION_STATUS = {"detected", "gap", "not_applicable"}
_VALID_EXPOSURE = {"internet", "intranet", "partner", "internal"}
_VALID_COVERAGE_STATE = {"threat", "considered", "not_applicable", "missing"}
_SEV_WEIGHT = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}
_CRIT_WEIGHT = {"critical": 1.5, "high": 1.25, "medium": 1.0, "low": 0.75}


def _clip(v: Any, lo: int, hi: int, default: int) -> int:
    try:
        n = int(v)
        return max(lo, min(hi, n))
    except Exception:
        return default


def _normalise(raw: Dict[str, Any], methodology: str) -> Dict[str, Any]:
    """Enforce the Phase 8 schema. Threats without evidence_refs are flagged
    `is_grounded=False` (kept, not dropped — UI demotes them so the
    consultant decides). Coverage matrix is derived if the LLM didn't emit one."""
    if not isinstance(raw, dict):
        raw = {}
    spec = METHODOLOGIES.get(methodology) or METHODOLOGIES[DEFAULT_METHODOLOGY]
    valid_cats = set(spec["categories"])
    default_cat = spec["default_category"]

    components = [_pick_fields(c, _COMPONENT_FIELDS) for c in (raw.get("components") or [])][:60]
    component_ids = {str(c.get("id") or "") for c in components}
    data_flows = [_pick_fields(d, _DATA_FLOW_FIELDS) for d in (raw.get("data_flows") or [])][:80]
    crit_map = {str(c.get("id") or ""): _str(c.get("criticality")).lower() or "medium" for c in components}

    # ── Trust boundaries (Phase 8 — new) ──────────────────────────────────
    trust_boundaries_raw = raw.get("trust_boundaries") or []
    trust_boundaries = []
    for i, tb in enumerate((trust_boundaries_raw if isinstance(trust_boundaries_raw, list) else [])[:25], 1):
        if not isinstance(tb, dict):
            continue
        crossed = tb.get("crossed_by_flow_ids") or []
        trust_boundaries.append({
            "id": _str(tb.get("id")) or f"tb{i}",
            "name": _str(tb.get("name"), default=f"boundary-{i}"),
            "from_zone": _str(tb.get("from_zone")).lower() or "unknown",
            "to_zone": _str(tb.get("to_zone")).lower() or "unknown",
            "description": _str(tb.get("description")),
            "crossed_by_flow_ids": crossed if isinstance(crossed, list) else [],
        })
    # If the LLM didn't supply any, derive one boundary per distinct (from_zone, to_zone)
    # pair seen in data_flows.
    if not trust_boundaries and components:
        zone_of = {c["id"]: _str(c.get("trust_zone")).lower() or "private" for c in components}
        seen_pairs = set()
        for f in data_flows:
            fz = zone_of.get(_str(f.get("from")), "")
            tz = zone_of.get(_str(f.get("to")), "")
            if fz and tz and fz != tz and (fz, tz) not in seen_pairs:
                seen_pairs.add((fz, tz))
                trust_boundaries.append({
                    "id": f"tb-auto-{len(trust_boundaries)+1}",
                    "name": f"{fz} → {tz}",
                    "from_zone": fz, "to_zone": tz,
                    "description": "Derived from data-flow zones (LLM did not emit explicit boundaries).",
                    "crossed_by_flow_ids": [],
                })

    # ── Entry points (Phase 8 — new) ──────────────────────────────────────
    entry_points_raw = raw.get("entry_points") or []
    entry_points = []
    for i, ep in enumerate((entry_points_raw if isinstance(entry_points_raw, list) else [])[:30], 1):
        if not isinstance(ep, dict):
            continue
        comp_id = _str(ep.get("component_id"))
        if comp_id and comp_id not in component_ids:
            comp_id = ""  # drop orphan
        exposure = _str(ep.get("exposure")).lower()
        if exposure not in _VALID_EXPOSURE:
            exposure = "internet"
        entry_points.append({
            "id": _str(ep.get("id")) or f"ep{i}",
            "kind": _str(ep.get("kind")) or "api",
            "name": _str(ep.get("name"), default=f"entry-{i}"),
            "component_id": comp_id,
            "exposure": exposure,
            "auth_required": bool(ep.get("auth_required", False)),
        })

    # ── Threats (Phase 8 — full expanded shape) ───────────────────────────
    threats_raw = raw.get("threats") or []
    threats: List[Dict[str, Any]] = []
    for i, t in enumerate(threats_raw[:80], 1):
        if not isinstance(t, dict):
            continue
        cat = _str(t.get("category")).lower()
        if cat not in valid_cats:
            cat = default_cat
        sev = _str(t.get("severity")).lower()
        if sev not in _SEV:
            sev = "medium"
        # evidence_refs is the new required-ish field. We accept the LLM's
        # output if it's a list of dicts; we also fold the legacy free-text
        # `evidence` into a refs entry so old models migrate naturally.
        evidence_refs_raw = t.get("evidence_refs") or []
        evidence_refs: List[Dict[str, Any]] = []
        if isinstance(evidence_refs_raw, list):
            for r in evidence_refs_raw[:8]:
                if not isinstance(r, dict):
                    continue
                kind = _str(r.get("kind")).lower()
                if kind not in ("asset", "finding", "cve", "capec", "attack"):
                    continue
                evidence_refs.append({
                    "kind": kind,
                    "id": _str(r.get("id"), default=""),
                    "label": _str(r.get("label"), default=""),
                })
        is_grounded = bool(evidence_refs)
        capec_refs = t.get("capec_refs") if isinstance(t.get("capec_refs"), list) else []
        attack_techniques = t.get("attack_techniques") if isinstance(t.get("attack_techniques"), list) else []
        cwe_refs = t.get("cwe_refs") if isinstance(t.get("cwe_refs"), list) else []
        blast_radius = t.get("blast_radius") if isinstance(t.get("blast_radius"), list) else []
        # Drop blast-radius entries that point at non-existent components.
        blast_radius = [_str(b) for b in blast_radius if _str(b) in component_ids][:20]
        linked_finding_ids = t.get("linked_finding_ids") if isinstance(t.get("linked_finding_ids"), list) else []
        owner_role = _str(t.get("owner_role")).lower()
        if owner_role not in _VALID_OWNER_ROLE:
            owner_role = "security"
        likelihood = _clip(t.get("likelihood"), 1, 5, 3)
        impact = _clip(t.get("impact"), 1, 5, 3)
        # Priority score: severity_weight × likelihood × impact × asset_criticality_weight.
        # Lands roughly in 1 .. 150 range; UI just sorts by it.
        asset_id = _str(t.get("asset_id"))
        asset_crit = crit_map.get(asset_id, "medium")
        priority_score = round(_SEV_WEIGHT.get(sev, 2.0) * likelihood * impact * _CRIT_WEIGHT.get(asset_crit, 1.0), 2)
        det_status = _str(t.get("detection_status")).lower()
        if det_status not in _VALID_DETECTION_STATUS:
            det_status = "gap"
        det_rules_raw = t.get("detection_rule_refs") or []
        det_rules = []
        if isinstance(det_rules_raw, list):
            for r in det_rules_raw[:5]:
                if isinstance(r, dict):
                    det_rules.append({
                        "platform": _str(r.get("platform"), default="generic"),
                        "rule_id": _str(r.get("rule_id")),
                    })
        status = _str(t.get("status")).lower()
        if status not in _VALID_THREAT_STATUS:
            status = "identified"
        residual_sev = _str(t.get("residual_severity")).lower()
        residual_sev = residual_sev if residual_sev in _SEV else None
        threat = {
            "id": _str(t.get("id")) or f"T{i:02d}",
            "category": cat,
            "asset_id": asset_id,
            "title": _str(t.get("title"), default="(untitled threat)"),
            "severity": sev,
            "likelihood": likelihood,
            "impact": impact,
            "priority_score": priority_score,
            "evidence": _str(t.get("evidence")),  # legacy free-text kept
            "evidence_refs": evidence_refs,
            "is_grounded": is_grounded,
            "capec_refs": capec_refs,
            "attack_techniques": attack_techniques,
            "cwe_refs": cwe_refs,
            "rationale": _str(t.get("rationale")),
            "attack_narrative": _str(t.get("attack_narrative")),
            "blast_radius": blast_radius,
            "owner_role": owner_role,
            "linked_finding_ids": linked_finding_ids,
            "detection_status": det_status,
            "detection_rule_refs": det_rules,
            "status": status,
            "decision_notes": _str(t.get("decision_notes")),
            "decided_by": _str(t.get("decided_by")),
            "decided_at": _str(t.get("decided_at")),
            "residual_severity": residual_sev,
            "residual_rationale": _str(t.get("residual_rationale")),
        }
        threats.append(threat)

    # ── Mitigations (Phase 8 — implementation_detail required, control_refs[]) ──
    mitigations_raw = raw.get("mitigations") or []
    mitigations: List[Dict[str, Any]] = []
    for i, m in enumerate(mitigations_raw[:120], 1):
        if not isinstance(m, dict):
            continue
        owner_role = _str(m.get("owner_role")).lower()
        if owner_role not in _VALID_OWNER_ROLE:
            owner_role = _str(m.get("owner")).lower() or "security"
            if owner_role not in _VALID_OWNER_ROLE:
                owner_role = "security"
        control_refs_raw = m.get("control_refs") or []
        control_refs = []
        if isinstance(control_refs_raw, list):
            for r in control_refs_raw[:6]:
                if isinstance(r, dict):
                    control_refs.append({
                        "framework": _str(r.get("framework")).lower(),
                        "control_id": _str(r.get("control_id")),
                    })
        # Fold legacy single control_id into the refs list when control_refs is empty
        legacy_control = _str(m.get("control_id"))
        if not control_refs and legacy_control:
            control_refs.append({"framework": "generic", "control_id": legacy_control})
        ev_link = m.get("evidence_link")
        if not isinstance(ev_link, dict):
            ev_link = None
        mitigations.append({
            "id": _str(m.get("id")) or f"M{i:02d}",
            "threat_id": _str(m.get("threat_id")),
            "action": _str(m.get("action")),
            "implementation_detail": _str(m.get("implementation_detail")),
            "control_id": legacy_control,  # keep for backward compat
            "control_refs": control_refs,
            "status": _str(m.get("status")).lower() if _str(m.get("status")).lower() in _STATUS else "open",
            "owner_role": owner_role,
            "owner": owner_role,  # legacy alias
            "evidence_link": ev_link,
        })

    # ── Coverage decisions (Phase 8B) ─────────────────────────────────────
    cov_raw = raw.get("coverage_decisions") or []
    coverage_decisions: List[Dict[str, Any]] = []
    seen_cells = set()
    if isinstance(cov_raw, list):
        for c in cov_raw[:600]:
            if not isinstance(c, dict):
                continue
            comp_id = _str(c.get("component_id"))
            cat = _str(c.get("category")).lower()
            if not comp_id or comp_id not in component_ids or cat not in valid_cats:
                continue
            state = _str(c.get("state")).lower()
            if state not in _VALID_COVERAGE_STATE:
                state = "missing"
            entry = {
                "component_id": comp_id,
                "category": cat,
                "state": state,
                "threat_id": _str(c.get("threat_id")) or None,
                "rationale": _str(c.get("rationale")),
            }
            coverage_decisions.append(entry)
            seen_cells.add((comp_id, cat))

    # Tiered fill-in: critical/high components should have ALL categories
    # covered. If the LLM missed some cells, mark them `missing` so the UI
    # can highlight gaps. We DON'T invent rationales — that's the consultant's
    # job (or a follow-up "fill gaps" LLM call from the matrix endpoint).
    threat_by_cell: Dict[tuple, str] = {}
    for t in threats:
        key = (t["asset_id"], t["category"])
        if key[0] and key[1] and key not in threat_by_cell:
            threat_by_cell[key] = t["id"]

    for c in components:
        comp_id = _str(c.get("id"))
        crit = _str(c.get("criticality")).lower() or "medium"
        # Decide which categories to require for this component's tier.
        if crit in ("critical", "high"):
            required_cats = list(valid_cats)
        elif crit == "medium":
            # Pick the categories that already have threats on this component,
            # plus the methodology's default; lower tiers don't force full coverage.
            required_cats = list({cat for (cid, cat) in threat_by_cell.keys() if cid == comp_id} | {default_cat})
        else:
            required_cats = [cat for (cid, cat) in threat_by_cell.keys() if cid == comp_id]
        for cat in required_cats:
            if (comp_id, cat) in seen_cells:
                continue
            # Auto-promote when a threat exists for this cell.
            if (comp_id, cat) in threat_by_cell:
                coverage_decisions.append({
                    "component_id": comp_id, "category": cat,
                    "state": "threat", "threat_id": threat_by_cell[(comp_id, cat)],
                    "rationale": "",
                })
            else:
                coverage_decisions.append({
                    "component_id": comp_id, "category": cat,
                    "state": "missing", "threat_id": None,
                    "rationale": "",
                })
            seen_cells.add((comp_id, cat))

    # ── DFD ───────────────────────────────────────────────────────────────
    dfd = _str(raw.get("dfd_mermaid")).strip()
    if dfd and not dfd.lstrip().startswith("flowchart"):
        dfd = "flowchart TD\n" + dfd
    if not dfd:
        lines = ["flowchart TD"]
        zones: Dict[str, List[Dict[str, Any]]] = {}
        for c in components:
            zone = _str(c.get("trust_zone")) or "private"
            zones.setdefault(zone, []).append(c)
        for zone, comps in zones.items():
            lines.append(f"  subgraph {zone.replace(' ', '_').upper()}[\"{zone.title().replace('-', ' ')}\"]")
            for c in comps:
                nid = _str(c['id']) or 'n'
                name = _str(c['name']) or '?'
                ctype = _str(c.get('type')) or ''
                # Two-line label: name on top, type subtle below
                label = f"{name}<br/><small>{ctype}</small>" if ctype else name
                lines.append(f'    {nid}["{label}"]')
            lines.append("  end")
        dfd = "\n".join(lines)

    return {
        "executive_summary": _str(raw.get("executive_summary")) or
            f"Threat model covers {len(components)} component(s) with {len(threats)} threats.",
        "components": components,
        "data_flows": data_flows,
        "trust_boundaries": trust_boundaries,
        "entry_points": entry_points,
        "threats": threats,
        "mitigations": mitigations,
        "coverage_decisions": coverage_decisions,
        "dfd_mermaid": dfd,
    }


# ── LLM call ─────────────────────────────────────────────────────────────────


async def _invoke_llm(
    scope: Dict[str, Any], framework: Optional[str], methodology: str,
    library: Optional[List[Dict[str, Any]]] = None,
    preset_components: Optional[List[Dict[str, Any]]] = None,
    preset_data_flows: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Call configured LLM. Returns the normalised model. Falls back to a
    deterministic skeleton when no provider is available."""
    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        llm = get_llm(temperature=0.2, max_tokens=4096)
    except Exception as exc:
        logger.warning("Threat modeler LLM unavailable, returning skeleton: %s", exc)
        return _skeleton(scope, methodology), {"provider": "fallback", "model": None, "tokens": 0}

    user_prompt = _build_user_prompt(
        scope, framework, methodology, library=library,
        preset_components=preset_components, preset_data_flows=preset_data_flows,
    )
    try:
        # Bound the call so a stalled provider connection can't leave the
        # threat model wedged in 'generating' forever (the worker would just
        # await indefinitely with nothing to interrupt it).
        result = await asyncio.wait_for(
            llm.ainvoke([
                SystemMessage(content=_build_system_prompt(methodology)),
                HumanMessage(content=user_prompt),
            ]),
            timeout=LLM_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning("Threat modeler LLM call timed out after %ss", LLM_TIMEOUT_SECONDS)
        return _skeleton(scope, methodology), {"provider": "fallback", "model": None, "tokens": 0,
                                               "error": f"LLM call timed out after {LLM_TIMEOUT_SECONDS}s"}
    except Exception as exc:
        logger.exception("Threat modeler LLM call failed")
        return _skeleton(scope, methodology), {"provider": "fallback", "model": None, "tokens": 0,
                                               "error": f"{type(exc).__name__}: {exc}"}

    text = result.content if hasattr(result, "content") else str(result)
    if isinstance(text, list):
        text = "\n".join(str(p) for p in text)

    # Be defensive about LLM trying to wrap in code fences despite instructions.
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[: -3]

    try:
        # Find first { ... last }
        start = text.find("{")
        end = text.rfind("}")
        parsed = json.loads(text[start:end + 1]) if start >= 0 and end > start else {}
    except Exception as exc:
        logger.warning("Threat modeler JSON parse failed: %s", exc)
        parsed = {}

    usage = getattr(result, "usage_metadata", None) or {}
    meta = {
        "provider": "configured",  # core.ai_providers picks the actual provider
        "model": getattr(llm, "model_name", None) or getattr(llm, "model", None),
        "tokens": int(usage.get("total_tokens") or 0),
    }
    return _normalise(parsed, methodology), meta


def _skeleton(scope: Dict[str, Any], methodology: str) -> Dict[str, Any]:
    """Deterministic fallback when no LLM is configured — purely architectural,
    no STRIDE narrative."""
    comps = []
    for i, a in enumerate(scope.get("assets", [])[:12], 1):
        zone = "public" if a["type"] in ("web/application", "web/endpoint") else "private"
        comps.append({
            "id": f"c{i}",
            "name": a["name"],
            "type": a["type"],
            "trust_zone": zone,
            "criticality": a.get("criticality") or "medium",
            "notes": "auto-stub",
        })
    raw = {
        "executive_summary": (
            "Skeleton threat model — no AI provider configured. "
            f"Architecture-only view of {len(comps)} asset(s)."
        ),
        "components": comps,
        "data_flows": [],
        "threats": [],
        "mitigations": [],
        "dfd_mermaid": "",
    }
    return _normalise(raw, methodology)


# ── Public entry point ──────────────────────────────────────────────────────


async def generate_threat_model(db: Session, model_id: str) -> ThreatModel:
    """Run the modeler against a ThreatModel row that's already persisted in
    `pending` state. Updates the row in-place with normalised output, sets
    status to `completed` / `failed`."""
    tm = db.query(ThreatModel).filter(ThreatModel.id == model_id).first()
    if not tm:
        raise ValueError(f"ThreatModel {model_id} not found")
    tm.status = "generating"
    db.commit()

    try:
        scope = _collect_scope(db, tm.client_id, tm.scope_type or "client", tm.scope_id)
        fw = tm.framework.value if hasattr(tm.framework, "value") else (tm.framework or None)
        methodology = (tm.methodology or DEFAULT_METHODOLOGY).lower()
        if methodology not in METHODOLOGIES:
            methodology = DEFAULT_METHODOLOGY
        library = _library_sample(db, methodology)
        # If the model was created from an uploaded diagram, the user-reviewed
        # components + data_flows are already on the row. Pass them through
        # to the LLM so it produces threats keyed to those exact IDs rather
        # than re-deriving an architecture from assets.
        preset_components = tm.components_json if tm.components_json else None
        preset_data_flows = tm.data_flows_json if tm.data_flows_json else None
        model, meta = await _invoke_llm(
            scope, fw, methodology, library=library,
            preset_components=preset_components, preset_data_flows=preset_data_flows,
        )

        # When the user supplied the architecture, keep their components +
        # flows verbatim; only the threats / mitigations / dfd / summary
        # come from the LLM. This means the LLM can't accidentally drop
        # or rename a component the user reviewed.
        if preset_components:
            tm.components_json = preset_components
            tm.data_flows_json = preset_data_flows or []
        else:
            tm.components_json = model["components"]
            tm.data_flows_json = model["data_flows"]
        tm.threats_json = model["threats"]
        tm.mitigations_json = model["mitigations"]
        tm.dfd_mermaid = model["dfd_mermaid"]
        tm.executive_summary = model["executive_summary"]
        # Phase 8 — persist the new completeness + coverage fields.
        tm.trust_boundaries_json = model.get("trust_boundaries") or []
        tm.entry_points_json = model.get("entry_points") or []
        tm.coverage_decisions = model.get("coverage_decisions") or []
        # Phase 8E — compute maturity scores at generation time (best-effort).
        try:
            from services.maturity_scorer import compute_maturity_scores
            tm.maturity_scores = compute_maturity_scores(db, tm.client_id, methodology, model["threats"])
        except Exception:
            logger.exception("maturity score computation failed (continuing)")
            tm.maturity_scores = {}
        tm.ai_provider = meta.get("provider")
        tm.ai_model = meta.get("model")
        tm.tokens_used = int(meta.get("tokens") or 0)
        tm.status = "completed"
        tm.generated_at = datetime.now(timezone.utc)
        if meta.get("error"):
            tm.error_message = meta["error"]
        db.commit()
        db.refresh(tm)
        return tm
    except Exception as exc:
        logger.exception("Threat model generation failed for %s", model_id)
        tm.status = "failed"
        tm.error_message = f"{type(exc).__name__}: {exc}"
        tm.generated_at = datetime.now(timezone.utc)
        db.commit()
        return tm


def generate_threat_model_bg(model_id: str) -> None:
    """Background-task entry point: opens its own session, awaits the
    coroutine, never raises out."""
    from db.database import SessionLocal
    import asyncio
    db = SessionLocal()
    try:
        asyncio.run(generate_threat_model(db, model_id))
    except Exception:
        logger.exception("generate_threat_model_bg failed for %s", model_id)
    finally:
        db.close()
