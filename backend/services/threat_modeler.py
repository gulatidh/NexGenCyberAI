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
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from api.models.models import (
    Asset, Client, Connector, Finding, Project, Scan, ThreatModel,
)

logger = logging.getLogger(__name__)


# ── Fixed schema fields (normaliser enforces these) ─────────────────────────


_COMPONENT_FIELDS = ("id", "name", "type", "trust_zone", "criticality", "notes")
_DATA_FLOW_FIELDS = ("from", "to", "protocol", "data", "encrypted", "notes")
_THREAT_FIELDS = (
    "id", "category", "asset_id", "title", "severity",
    "evidence", "capec_refs", "attack_techniques", "rationale",
)
_MITIGATION_FIELDS = ("id", "threat_id", "action", "control_id", "status", "owner")

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
    asset_rows = [{
        "id": a.id,
        "name": a.name or a.external_id or a.id,
        "type": a.asset_type or "unknown",
        "external_id": a.external_id,
        "criticality": getattr(a, "criticality", None) or "medium",
    } for a in assets]

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


_SYSTEM_PROMPT_TMPL = """You are a senior cybersecurity threat modeler. You apply the {label}
methodology to architecture + finding evidence. {description}

Output STRICT JSON only — no prose, no markdown fences, no commentary
outside the JSON object. The schema:

{{
  "executive_summary": "<2-4 sentence CISO-level overview>",
  "components": [
    {{ "id": "<short-slug>", "name": "<asset name>", "type": "<vm|storage|identity|repo|endpoint|database|api|queue|secret-store|other>",
      "trust_zone": "<public|dmz|private|data-tier|management>",
      "criticality": "<critical|high|medium|low>",
      "notes": "<one-line>" }}
  ],
  "data_flows": [
    {{ "from": "<component id>", "to": "<component id>",
      "protocol": "<https|sql|ssh|smb|grpc|amqp|other>",
      "data": "<credentials|pii|financial|telemetry|config|other>",
      "encrypted": <true|false>,
      "notes": "<one-line>" }}
  ],
  "threats": [
    {{ "id": "T01",
      "category": "<one of: {categories_csv}>",
      "asset_id": "<component id>",
      "title": "<short threat statement>",
      "severity": "<critical|high|medium|low|info>",
      "evidence": "<reference a finding, a CVE, or 'no evidence — derived from {label}'>",
      "capec_refs": ["CAPEC-NN"],
      "attack_techniques": ["T1234"],
      "rationale": "<2-3 sentences justifying severity and evidence>" }}
  ],
  "mitigations": [
    {{ "id": "M01", "threat_id": "T01",
      "action": "<concrete remediation step>",
      "control_id": "<NIST/CIS/OWASP control ID if applicable>",
      "status": "open",
      "owner": "<role or team — security|platform|appdev|grc>" }}
  ],
  "dfd_mermaid": "flowchart TD\\n  ..."
}}

Rules:
- The dfd_mermaid value MUST be valid Mermaid `flowchart TD` syntax. Use the component
  IDs as node IDs. Group nodes by trust zone using `subgraph` blocks.
- Every threat must have at least one mitigation.
- Prefer evidence-grounded threats: if a finding cites an open SSH port,
  raise the relevant threat category around that port, not a generic one.
- Use the connector topology to identify trust boundaries (e.g. internet
  → public; Entra ID → identity zone).
- Aim for 8-15 components, 10-25 threats. Quality over volume.
- Third-person, executive tone. No greetings, no questions to the user.
- The `category` field MUST be exactly one of the listed values for {label}.
"""


def _build_system_prompt(methodology: str) -> str:
    spec = METHODOLOGIES.get(methodology) or METHODOLOGIES[DEFAULT_METHODOLOGY]
    return _SYSTEM_PROMPT_TMPL.format(
        label=spec["label"],
        description=spec["description"],
        categories_csv="|".join(spec["categories"]),
    )


def _build_user_prompt(scope: Dict[str, Any], framework: Optional[str], methodology: str) -> str:
    spec = METHODOLOGIES.get(methodology) or METHODOLOGIES[DEFAULT_METHODOLOGY]
    parts: List[str] = [
        "## Scope",
        f"Client: {scope['client_name']}",
        f"Scope type: {scope['scope_type']}" + (f" (id={scope['scope_id']})" if scope.get("scope_id") else ""),
        f"Connectors in play: {', '.join(scope['connector_types']) or 'none'}",
        f"Framework target: {framework or 'NIST CSF (default)'}",
        f"Methodology: {spec['label']}",
        "",
        "## Asset inventory (sample)",
    ]
    for a in scope["assets"][:60]:
        parts.append(f"- [{a['type']}] {a['name']} (criticality={a['criticality']})")
    if not scope["assets"]:
        parts.append("- (no assets discovered for this scope)")

    parts.append("")
    parts.append(f"## Finding signals — {scope['finding_count']} total: {scope['findings_severity_counts']}")
    for f in scope["findings"][:25]:
        parts.append(f"- [{f['severity']}] {f['title']} on `{f['resource'] or 'n/a'}` "
                     f"(CVE={f['cve'] or '—'}, CVSS={f['cvss'] or '—'}, control={f['control'] or '—'})")
    if not scope["findings"]:
        parts.append("- (no findings yet — model purely from architecture)")

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


def _normalise(raw: Dict[str, Any], methodology: str) -> Dict[str, Any]:
    """Enforce schema regardless of LLM compliance."""
    if not isinstance(raw, dict):
        raw = {}
    spec = METHODOLOGIES.get(methodology) or METHODOLOGIES[DEFAULT_METHODOLOGY]
    valid_cats = set(spec["categories"])
    default_cat = spec["default_category"]

    components = [_pick_fields(c, _COMPONENT_FIELDS) for c in (raw.get("components") or [])][:50]
    data_flows = [_pick_fields(d, _DATA_FLOW_FIELDS) for d in (raw.get("data_flows") or [])][:60]
    threats_raw = raw.get("threats") or []
    threats = []
    for i, t in enumerate(threats_raw[:50], 1):
        t = _pick_fields(t, _THREAT_FIELDS)
        t["id"] = _str(t["id"]) or f"T{i:02d}"
        # Accept "stride" as a legacy alias for "category" so prior models
        # still render.
        cat = _str(t.get("category") or "").lower()
        if cat not in valid_cats:
            cat = default_cat
        t["category"] = cat
        t["severity"] = _str(t["severity"]).lower() if _str(t["severity"]).lower() in _SEV else "medium"
        t["capec_refs"] = t.get("capec_refs") if isinstance(t.get("capec_refs"), list) else []
        t["attack_techniques"] = t.get("attack_techniques") if isinstance(t.get("attack_techniques"), list) else []
        threats.append(t)
    mitigations_raw = raw.get("mitigations") or []
    mitigations = []
    for i, m in enumerate(mitigations_raw[:80], 1):
        m = _pick_fields(m, _MITIGATION_FIELDS)
        m["id"] = _str(m["id"]) or f"M{i:02d}"
        m["status"] = _str(m["status"]).lower() if _str(m["status"]).lower() in _STATUS else "open"
        mitigations.append(m)

    dfd = _str(raw.get("dfd_mermaid")).strip()
    if dfd and not dfd.lstrip().startswith("flowchart"):
        # Anything not starting with `flowchart` — wrap it so Mermaid still renders.
        dfd = "flowchart TD\n" + dfd
    if not dfd:
        # Skeleton DFD from component list
        lines = ["flowchart TD"]
        zones: Dict[str, List[str]] = {}
        for c in components:
            zone = _str(c.get("trust_zone")) or "private"
            zones.setdefault(zone, []).append(c)
        for zone, comps in zones.items():
            lines.append(f"  subgraph {zone.replace(' ', '_').upper()}")
            for c in comps:
                lines.append(f"    {_str(c['id']) or 'n'}[\"{_str(c['name']) or '?'}\"]")
            lines.append("  end")
        dfd = "\n".join(lines)

    return {
        "executive_summary": _str(raw.get("executive_summary")) or
            f"Threat model covers {len(components)} component(s) with {len(threats)} STRIDE-derived threats.",
        "components": components,
        "data_flows": data_flows,
        "threats": threats,
        "mitigations": mitigations,
        "dfd_mermaid": dfd,
    }


# ── LLM call ─────────────────────────────────────────────────────────────────


async def _invoke_llm(
    scope: Dict[str, Any], framework: Optional[str], methodology: str,
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

    user_prompt = _build_user_prompt(scope, framework, methodology)
    try:
        result = await llm.ainvoke([
            SystemMessage(content=_build_system_prompt(methodology)),
            HumanMessage(content=user_prompt),
        ])
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
        model, meta = await _invoke_llm(scope, fw, methodology)

        tm.components_json = model["components"]
        tm.data_flows_json = model["data_flows"]
        tm.threats_json = model["threats"]
        tm.mitigations_json = model["mitigations"]
        tm.dfd_mermaid = model["dfd_mermaid"]
        tm.executive_summary = model["executive_summary"]
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
