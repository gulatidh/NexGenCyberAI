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
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from api.models.models import (
    Asset, AssetStatus, Client, Connector, Finding, Project, Risk, Scan, ThreatLibrary, ThreatModel,
)

logger = logging.getLogger(__name__)


# ── Fixed schema fields (normaliser enforces these) ─────────────────────────


_COMPONENT_FIELDS = ("id", "name", "type", "dfd_type", "is_threat_actor", "threat_actor_type", "trust_zone", "criticality", "notes")
_DATA_FLOW_FIELDS = ("from", "to", "protocol", "data", "encrypted", "notes",
                     "port", "direction", "trust_boundary_crossing", "exposure",
                     "authentication_required")
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

# Output-token budget for the model JSON. The deliverable schema is large
# (components + data_flows + threats + mitigations + trust_boundaries +
# entry_points + coverage_decisions); at the old 4096 cap the JSON was
# truncated mid-document for any non-trivial scope, so it failed to parse and
# the model came back empty. gpt-4.1-mini (the configured deployment) allows
# up to 32k output tokens — give it generous headroom.
THREAT_MODEL_MAX_TOKENS = 16000

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
    scan_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build the context dict that gets injected into the LLM prompt.

    When `scan_ids` is given (scope_type='scans'), findings come from exactly
    those scans and assets are narrowed to the connectors those scans ran
    against — so the model reflects one environment instead of a messy
    client-wide aggregate."""
    client = db.query(Client).filter(Client.id == client_id).first()
    client_name = client.name if client else "Unknown Client"

    scan_ids = [s for s in (scan_ids or []) if s] or None
    # Connectors exercised by the selected scans — used to scope assets.
    scan_connector_ids: List[str] = []
    if scan_ids:
        scan_connector_ids = [
            cid for (cid,) in db.query(Scan.connector_id).filter(Scan.id.in_(scan_ids)).all() if cid
        ]

    # ── Assets in scope ────
    assets_q = db.query(Asset).filter(Asset.client_id == client_id)
    if scope_type == "asset" and scope_id:
        # Explicit single-asset scope — model exactly that, stale or not.
        assets_q = assets_q.filter(Asset.id == scope_id)
    else:
        assets_q = assets_q.filter(Asset.status == AssetStatus.ACTIVE.value)
        # Require a recognised asset class — drop the 'other' catch-all and
        # untyped (NULL/empty) assets, which only add noise to the model.
        assets_q = assets_q.filter(
            Asset.asset_class.isnot(None), Asset.asset_class != "", Asset.asset_class != "other",
        )
        if scan_ids and scan_connector_ids:
            assets_q = assets_q.filter(Asset.connector_id.in_(scan_connector_ids))
        elif scope_type == "project" and scope_id:
            assets_q = assets_q.filter(Asset.project_id == scope_id)
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
            "asset_class": getattr(a, "asset_class", None) or "",
            "external_id": a.external_id,
            "provider": provider,
            "region": getattr(a, "region", None) or "",
            "criticality": getattr(a, "criticality", None) or "medium",
        })

    # ── Recent findings (last 50, severity-ordered) ────
    findings_q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id)
    )
    if scan_ids:
        findings_q = findings_q.filter(Finding.scan_id.in_(scan_ids))
    findings_q = findings_q.order_by(
        Finding.cvss_score.desc(), Finding.created_at.desc()
    ).limit(50)
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

    # ── Risk register / assessment (top 25 by score) ────
    risks = (
        db.query(Risk)
        .filter(Risk.client_id == client_id)
        .order_by(Risk.risk_score.desc())
        .limit(25)
        .all()
    )
    risk_rows = []
    for r in risks:
        risk_rows.append({
            "id": r.id,
            "title": (r.title or "")[:160],
            "category": r.category or "",
            "score": float(r.risk_score) if r.risk_score is not None else None,
            "likelihood": getattr(r, "likelihood", None),
            "impact": getattr(r, "impact", None),
            "status": r.status or "open",
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

    # ── Raw resource configuration (from scan.raw_context) ────
    # Load the actual security config snapshots so the LLM reasons about
    # real misconfigurations, not just asset names.
    resource_configs: List[Dict[str, Any]] = []
    try:
        scans_q = db.query(Scan).filter(
            Scan.client_id == client_id,
            Scan.raw_context.isnot(None),
        )
        if scan_ids:
            scans_q = scans_q.filter(Scan.id.in_(scan_ids))
        else:
            # Most recent scan per connector for client-wide scope
            scans_q = scans_q.order_by(Scan.completed_at.desc()).limit(5)
        raw_scans = scans_q.all()
        seen_resource_ids: set = set()
        for s in raw_scans:
            try:
                resources = json.loads(s.raw_context or "[]")
                for r in resources:
                    rid = r.get("id") or r.get("name") or ""
                    if rid in seen_resource_ids:
                        continue
                    seen_resource_ids.add(rid)
                    resource_configs.append(r)
                    if len(resource_configs) >= 60:
                        break
            except Exception:
                pass
            if len(resource_configs) >= 60:
                break
    except Exception:
        pass

    return {
        "client_name": client_name,
        "scope_type": scope_type,
        "scope_id": scope_id,
        "asset_count": len(asset_rows),
        "assets": asset_rows,
        "finding_count": len(finding_rows),
        "findings_severity_counts": dict(sev_counts),
        "findings": finding_rows,
        "risk_count": len(risk_rows),
        "risks": risk_rows,
        "connector_types": connector_types,
        "resource_configs": resource_configs,
    }


# ── Prompt building ──────────────────────────────────────────────────────────


_SYSTEM_PROMPT_TMPL = """You are a senior cybersecurity threat modeler producing a CONSULTANT-GRADE deliverable.
You apply the {label} methodology rigorously. {description}

Output STRICT JSON only — no prose, no markdown fences, no commentary outside the JSON object. The schema:

{{
  "executive_summary": "<2-4 sentence CISO-level overview>",
  "components": [
    {{ "id": "<short-slug>", "name": "<asset name>",
      "type": "<vm|storage|identity|repo|endpoint|database|api|queue|secret-store|threat_actor|other>",
      "dfd_type": "<external_entity|process|data_store>",
      "is_threat_actor": <true|false>,
      "threat_actor_type": "<external_attacker|insider_threat|nation_state|script_kiddie|vendor_risk|null>",
      "trust_zone": "<Internet|DMZ|Corporate Network|Vendor Cloud|Database Tier|Management Zone>",
      "criticality": "<critical|high|medium|low>",
      "notes": "<one-line>" }}
  ],
  SCHEMA NOTES:
  - dfd_type: external_entity = users, browsers, threat actors, CDN, external APIs, 3rd-party services; process = anything that transforms/handles data (web apps, APIs, microservices, VMs, containers, auth providers); data_store = data at rest (databases, blob storage, secret stores, file repos).
  - ALWAYS include 1-3 threat actor components (is_threat_actor:true) representing realistic adversaries for this environment — e.g. "External Attacker", "Malicious Insider", "Compromised Vendor". Place them in the "Internet" trust_zone (or "Corporate Network" for insider). Give them dfd_type:"external_entity".
  - trust_zone must use SECURITY DOMAIN names — NOT generic network names:
      Internet = untrusted external zone (attackers, internet users, external APIs)
      DMZ = semi-trusted perimeter (load balancers, WAF, CDN, reverse proxies)
      Corporate Network = internally-owned trusted systems
      Vendor Cloud = third-party cloud services (AWS, Azure services, SaaS)
      Database Tier = data stores requiring restricted access
      Management Zone = privileged admin systems (SIEM, bastion, key vault, monitoring)
  "data_flows": [
    {{ "from": "<component id>", "to": "<component id>",
      "label": "<SourceName to DestinationName>",
      "is_attack_vector": <true|false>,
      "protocol": "<https|sql|ssh|smb|grpc|amqp|dns|other>",
      "port": "<port number e.g. 443, 5432, 8080>",
      "data": "<credentials|pii|financial|telemetry|config|other>",
      "encrypted": <true|false>,
      "direction": "<ingress|egress|internal|bidirectional>",
      "trust_boundary_crossing": <true|false>,
      "exposure": "<internet_facing|private|partner_network>",
      "authentication_required": <true|false>,
      "notes": "<one-line>" }}
  ],
  "trust_boundaries": [
    {{ "id": "tb1", "name": "<e.g. Corporate Boundary|Vendor Boundary|Internet Boundary|Database Server Boundary>",
      "from_zone": "<Internet|DMZ|Corporate Network|Vendor Cloud|Database Tier|Management Zone>",
      "to_zone": "<Internet|DMZ|Corporate Network|Vendor Cloud|Database Tier|Management Zone>",
      "boundary_type": "<corporate|vendor|internet|server|dmz|cloud>",
      "description": "<one-line>", "crossed_by_flow_ids": ["f1","f2"] }}
  ],
  NOTE — produce named trust boundaries like "Corporate Boundary" (wraps Corporate Network zone), "Vendor Boundary" (wraps Vendor Cloud zone), "Database Server Boundary" (wraps Database Tier). These boundaries must have meaningful SECURITY context — not just "public→private".
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
      "likelihood": <1-10: how probable exploitation is>,
      "impact": <1-10: damage if exploited>,
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
  "adversary_profiles": [
    {{ "id": "AP01",
      "name": "<threat actor name e.g. APT29 / FIN7 / ransomware-generic / insider>",
      "type": "nation_state|criminal|hacktivist|insider|opportunistic",
      "motivation": "espionage|financial|disruption|activism|sabotage",
      "sophistication": "high|medium|low",
      "targeted_assets": ["<component_id>"],
      "likely_techniques": ["T1566.001", "T1078"],
      "threat_ids": ["T01", "T03"],
      "likelihood": "<1-10>",
      "rationale": "<2-3 sentences grounding this actor in the client's sector and asset inventory>"
    }}
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

2b. THREAT ACTORS — include 1-3 threat actor components (is_threat_actor:true, dfd_type:external_entity) that represent realistic adversaries. For each threat actor, produce at least one data_flow (is_attack_vector:true) from that actor to the component they would initially target. Attack vector flows show HOW the adversary enters the system on the DFD. Label them e.g. "Attacker → Login Endpoint" or "Malicious Insider → Key Vault". Trust boundaries MUST reflect security ownership — use "Corporate Boundary", "Vendor Boundary", "Database Server Boundary" etc., NOT network zone names.

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

10. PRIORITY — likelihood and impact are 1-10 integers (rate each threat independently so they vary;
    do NOT give every threat of the same severity the same numbers). Severity tier is your overall call.
    The platform computes priority_score = severity_weight × likelihood × impact × asset_criticality_weight,
    and the Risk Register score = likelihood × impact / 10.

11. Use category values ONLY from this set for {label}: {categories_csv}.

12. Third-person, executive tone. No greetings, no questions, no 'I can also', no apologies.

13. ADVERSARY PROFILES — produce 2-4 adversary_profiles entries representing realistic threat actors
    for this client's sector and asset profile. At least one must be a criminal/opportunistic actor.
    Ground each actor in the supplied asset inventory — cite real component IDs in targeted_assets.

14. TRAFFIC FLOW DIRECTION — classify EVERY data_flow with direction:
    - ingress: traffic entering the system from outside (users, internet APIs, third-party webhooks)
    - egress: traffic leaving the system to external services (SaaS APIs, cloud services, CDN)
    - internal: component-to-component within the same trust zone
    - bidirectional: two-way (e.g. database queries + results, synchronous RPC)
    Set trust_boundary_crossing=true for any flow that crosses between trust zones (e.g. DMZ → private).
    Set exposure=internet_facing for components reachable from the public internet.
    Always populate the port field where the protocol has a well-known port (443, 5432, 22, etc.).
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
                       preset_data_flows: Optional[List[Dict[str, Any]]] = None,
                       analyst_notes: Optional[str] = None) -> str:
    spec = METHODOLOGIES.get(methodology) or METHODOLOGIES[DEFAULT_METHODOLOGY]
    parts: List[str] = [
        "## Scope",
        f"Client: {scope['client_name']}",
        f"Scope type: {scope['scope_type']}" + (f" (id={scope['scope_id']})" if scope.get("scope_id") else ""),
        f"Connectors in play: {', '.join(scope['connector_types']) or 'none'}",
        f"Framework target: {framework or 'NIST CSF (default)'}",
        f"Methodology: {spec['label']}",
    ]

    # Analyst guidance — authoritative context the user wants the model to honour.
    if analyst_notes and analyst_notes.strip():
        parts.append("")
        parts.append("## Analyst guidance (AUTHORITATIVE — incorporate this into the analysis)")
        parts.append(analyst_notes.strip()[:4000])

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

    # ── Risk assessment context ────
    parts.append("")
    parts.append(f"## Risk assessment — {scope.get('risk_count', 0)} tracked risks (Risk Register)")
    if scope.get("risks"):
        parts.append("Align threats with the customer's existing risk posture. Where a threat reinforces a "
                     "tracked risk, reference it in `evidence_refs` (kind='finding') and keep severities consistent.")
        for r in scope["risks"][:20]:
            parts.append(f"- risk_id={r['id']} [{r.get('category') or 'uncategorised'}] {r['title']} "
                         f"(score={r.get('score') if r.get('score') is not None else '—'}, "
                         f"L={r.get('likelihood') or '—'}/I={r.get('impact') or '—'}, status={r.get('status')})")
    else:
        parts.append("- (no risks recorded yet — propose the risks this architecture introduces)")

    # ── Raw resource configuration ────
    resource_configs = scope.get("resource_configs") or []
    if resource_configs:
        parts.append("")
        parts.append(
            f"## Raw resource configuration — {len(resource_configs)} resources with actual security settings"
        )
        parts.append(
            "IMPORTANT: Use this configuration data to identify misconfiguration gaps the finding list may not capture. "
            "Evaluate each resource's `config` dict for missing security controls (e.g. encryption disabled, "
            "public access enabled, MFA not enforced, logging off, stale credentials, open ports)."
        )
        for rc in resource_configs:
            name = rc.get("name") or rc.get("id") or "unknown"
            rtype = rc.get("type") or "resource"
            config = rc.get("config") or {}
            # Truncate config to avoid token explosion
            config_str = json.dumps(config, default=str)[:800]
            parts.append(f"- [{rtype}] {name}: {config_str}")

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


def _mm_id(raw_id: Any) -> str:
    """Mermaid-safe node id: alphanumerics + underscore, never empty, never
    leading digit (Mermaid rejects those)."""
    s = re.sub(r"[^A-Za-z0-9_]", "_", _str(raw_id)).strip("_")
    if not s:
        return "n"
    return ("n_" + s) if s[0].isdigit() else s


def _mm_label(text: Any) -> str:
    """Sanitise text for use inside a quoted Mermaid label. Strips the
    characters that break the parser even when quoted, collapses whitespace,
    and caps length."""
    s = _str(text).replace('"', "'").replace("|", "/")
    s = s.replace("[", "(").replace("]", ")").replace("{", "(").replace("}", ")")
    s = re.sub(r"[<>]", "", s)          # avoid stray HTML-ish tokens in labels
    s = " ".join(s.split())
    return s[:80]


# Service-type glyphs prepended to DFD nodes so each component reads as an
# icon + name. Matched on name+type keywords (covers the common cloud
# services across AWS/Azure/GCP without a heavyweight icon set).
_SVC_ICONS = [
    (("database", "db", "sql", "postgres", "mysql", "mongo", "rds", "cosmos", "dynamo", "aurora", "spanner"), "🗄️"),
    (("storage", "bucket", "blob", "s3", "object store", "gcs", "datalake", "data lake"), "🪣"),
    (("queue", "topic", "kafka", "sqs", "sns", "event", "bus", "pubsub", "service bus", "kinesis"), "📨"),
    (("secret", "key vault", "keyvault", "kms", "vault", "secrets manager"), "🔑"),
    (("identity", "iam", "auth", "entra", "azure ad", "active directory", "okta", "cognito", "sso", "oauth"), "👤"),
    (("function", "lambda", "serverless", "cloud function", "azure function"), "⚡"),
    (("container", "kubernetes", "k8s", "pod", "aks", "eks", "gke", "docker", "fargate", "ecs"), "📦"),
    (("api", "gateway", "apim", "endpoint", "rest", "graphql", "app gateway"), "🔌"),
    (("cache", "redis", "memcache", "elasticache"), "🧠"),
    (("cdn", "frontend", "web", "spa", "website", "app service", "webapp", "cloudfront"), "🌐"),
    (("firewall", "waf", "nsg", "security group", "shield"), "🧱"),
    (("load balancer", "load-balancer", "lb", "ingress", "traffic manager", "front door", "elb", "alb"), "🔀"),
    (("vm", "compute", "server", "ec2", "virtual machine", "instance", "host", "vmss", "gce"), "🖥️"),
    (("monitor", "log", "siem", "sentinel", "cloudwatch", "stackdriver"), "📊"),
    (("user", "client", "browser", "customer", "actor", "external", "internet"), "👥"),
]


def _svc_icon(text: str) -> str:
    t = (text or "").lower()
    for keys, icon in _SVC_ICONS:
        if any(k in t for k in keys):
            return icon
    return "⚙️"


def _component_type(text: str) -> str:
    """Map an asset's type/name to a DFD component type vocabulary."""
    t = (text or "").lower()
    table = [
        (("database", "db", "sql", "postgres", "mysql", "mongo", "rds", "cosmos", "dynamo", "aurora"), "database"),
        (("storage", "bucket", "blob", "s3", "object", "datalake", "data lake", "gcs"), "storage"),
        (("queue", "topic", "kafka", "sqs", "sns", "event", "bus", "pubsub", "service bus"), "queue"),
        (("secret", "vault", "kms", "keyvault"), "secret-store"),
        (("identity", "iam", "auth", "entra", "active directory", "okta", "cognito"), "identity"),
        (("api", "gateway", "apim", "endpoint", "rest", "graphql"), "api"),
        (("repo", "git", "source", "codeql", "sonar"), "repo"),
        (("vm", "compute", "server", "ec2", "instance", "host", "vmss", "function", "lambda",
          "container", "aks", "eks", "gke", "webapp", "app service", "web", "frontend", "cdn"), "endpoint"),
    ]
    for keys, typ in table:
        if any(k in t for k in keys):
            return typ
    return "other"


def _infer_zone(text: str) -> str:
    """Security-domain trust zone from asset name/type/external_id signals.

    Uses security-ownership vocabulary (Corporate Network, DMZ, etc.) not
    network-tier names.  Azure resource IDs encode the resource provider
    (e.g. Microsoft.Sql/servers) which is far more reliable than keyword
    matching on a display name, so those paths are checked first.
    """
    t = (text or "").lower()

    # ── Azure resource-provider paths (external_id format) ────────────────
    # Microsoft.Network/applicationGateways → DMZ
    if any(k in t for k in (
        "microsoft.network/applicationgateways",
        "microsoft.network/frontdoors",
        "microsoft.network/trafficmanagerprofiles",
        "microsoft.cdn",
        "microsoft.network/loadbalancers",
    )):
        return "DMZ"
    # Azure data services → Database Tier
    if any(k in t for k in (
        "microsoft.sql/",
        "microsoft.dbformysql",
        "microsoft.dbforpostgresql",
        "microsoft.dbformariadb",
        "microsoft.documentdb",
        "microsoft.storage/storageaccounts",
        "microsoft.synapse",
        "microsoft.datalakestore",
        "microsoft.databricks",
        "microsoft.cache/redis",
    )):
        return "Database Tier"
    # Azure security / management → Management Zone
    if any(k in t for k in (
        "microsoft.keyvault",
        "microsoft.security",
        "microsoft.operationalinsights",
        "microsoft.insights",
        "microsoft.sentinel",
        "microsoft.automation",
        "microsoft.managedidentity",
        "microsoft.network/bastionhosts",
        "microsoft.network/privatednszones",
    )):
        return "Management Zone"
    # Azure web / compute / container → app stays inside Corporate Network
    if any(k in t for k in (
        "microsoft.web/",
        "microsoft.compute/",
        "microsoft.containerservice/",
        "microsoft.containerregistry/",
        "microsoft.app/",
        "microsoft.servicefabric",
        "microsoft.logic/",
        "microsoft.apimanagement",
        "microsoft.servicebus",
        "microsoft.eventhub",
        "microsoft.signalrservice",
    )):
        return "Corporate Network"
    # Any other Microsoft/Azure resource → customer-owned, Corporate Network
    if "microsoft." in t or "/providers/microsoft" in t:
        return "Corporate Network"

    # ── AWS resource ARN / type patterns ──────────────────────────────────
    if any(k in t for k in (
        "cloudfront", "apigateway", "aws::elasticloadbalancing",
        "wafv2", "aws::route53",
    )):
        return "DMZ"
    if any(k in t for k in (
        "aws::rds", "aws::dynamodb", "aws::s3", "aws::redshift",
        "aws::elasticache", "aws::glue", "aws::athena",
        ":s3:::", ":rds:",
    )):
        return "Database Tier"
    if any(k in t for k in (
        "aws::secretsmanager", "aws::kms", "aws::iam",
        "aws::cloudwatch", "aws::guardduty", "aws::securityhub",
        "aws::ssm",
    )):
        return "Management Zone"
    # Generic AWS compute → Corporate Network (customer's own infra)
    if any(k in t for k in (
        "aws::ec2", "aws::ecs", "aws::eks", "aws::lambda",
        "aws::elasticbeanstalk", "arn:aws:",
    )):
        return "Corporate Network"

    # ── GCP resource paths ────────────────────────────────────────────────
    if "cloudsql" in t or "bigquery" in t or "firestore" in t or "spanner" in t:
        return "Database Tier"
    if "secretmanager" in t or "cloudkms" in t or "logging.googleapis" in t:
        return "Management Zone"
    if any(k in t for k in ("compute.googleapis", "container.googleapis",
                             "appengine.googleapis", "run.googleapis")):
        return "Corporate Network"

    # ── Generic display-name keywords (fallback) ──────────────────────────
    if any(k in t for k in (
        "cdn", "waf", "edge", "front door", "load balancer", "load_balancer",
        "ingress", "dmz", "perimeter", "reverse proxy", "api gateway",
    )):
        return "DMZ"
    if any(k in t for k in (
        "database", " db ", "_db_", "sql", "storage", "bucket", "blob",
        "warehouse", "lake", "cosmos", "dynamo", "rds", "cache", "redis",
    )):
        return "Database Tier"
    if any(k in t for k in (
        "secret", "vault", "kms", "keyvault", "key vault",
        "bastion", "admin", "mgmt", "siem", "sentinel",
        " monitor", "_monitor", "logging",
    )):
        return "Management Zone"
    # Third-party SaaS / external APIs → Vendor Cloud
    if any(k in t for k in (
        "saas", "third.party", "third_party", "external.api", "external_api",
        "partner", "vendor",
    )):
        return "Vendor Cloud"

    return "Corporate Network"


def _components_from_assets(assets: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Deterministically derive DFD components from the scoped asset inventory,
    so the architecture is identical for STRIDE / MITRE / any rerun of the same
    scope — only the threat lens changes. Empty when the scope has no assets
    (the caller then falls back to LLM-inferred architecture)."""
    comps: List[Dict[str, Any]] = []
    for i, a in enumerate(list(assets or [])[:60]):
        name = _str(a.get("name")) or _str(a.get("id")) or f"component {i+1}"
        # Build hay from every signal available — external_id is the most
        # reliable for cloud assets (e.g. Microsoft.Sql/servers/... for Azure)
        hay = " ".join(filter(None, [
            a.get("name", ""),
            a.get("type", ""),
            a.get("asset_class", ""),
            a.get("provider", ""),
            (a.get("external_id") or "").lower(),
        ]))
        comps.append({
            # Short, stable IDs (c1, c2, …) the LLM can echo reliably when
            # keying threats/flows/coverage back to a component — asset UUIDs
            # don't survive an LLM round-trip.
            "id": f"c{i+1}",
            "name": name,
            "type": _component_type(hay),
            "dfd_type": (
                "data_store" if _component_type(hay) in ("database", "storage", "secret-store", "repo")
                else "external_entity" if _component_type(hay) == "endpoint"
                else "process"
            ),
            "is_threat_actor": False,
            "threat_actor_type": None,
            "trust_zone": _infer_zone(hay),
            "criticality": _str(a.get("criticality")) or "medium",
            "notes": "",
        })
    return comps


def _build_mermaid(components: List[Dict[str, Any]], data_flows: List[Dict[str, Any]]) -> str:
    """Deterministically render a valid Mermaid `flowchart TD` from the
    structured DFD. Nodes are grouped into trust-zone subgraphs; edge labels
    are quoted + sanitised so protocol/data annotations like
    `https (pii, encrypted)` can't break the parser."""
    lines: List[str] = ["flowchart TD"]
    id_map: Dict[str, str] = {}
    zones: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    for c in components:
        cid = _str(c.get("id"))
        if not cid:
            continue
        nid = _mm_id(cid)
        id_map[cid] = nid
        zones.setdefault(_str(c.get("trust_zone")) or "private", []).append((nid, c))

    for zone, comps in zones.items():
        zlabel = _mm_label(zone.title().replace("-", " ")) or "Zone"
        lines.append(f'  subgraph {_mm_id("zone_" + zone)}["{zlabel}"]')
        for nid, c in comps:
            name = _mm_label(c.get("name") or c.get("id") or "?")
            ctype = _mm_label(c.get("type") or "")
            icon = _svc_icon(f"{c.get('name','')} {c.get('type','')}")
            label = (f"{icon} {name}<br/><small>{ctype}</small>" if ctype
                     else f"{icon} {name}")
            lines.append(f'    {nid}["{label}"]')
        lines.append("  end")

    _DIR_ICON = {"ingress": "⬇", "egress": "⬆", "bidirectional": "⇅", "internal": ""}
    for f in data_flows or []:
        frm, to = _str(f.get("from")), _str(f.get("to"))
        if not frm or not to:
            continue
        a = id_map.get(frm) or _mm_id(frm)
        b = id_map.get(to) or _mm_id(to)
        direction = _str(f.get("direction")) or "internal"
        port = _str(f.get("port"))
        proto = _str(f.get("protocol"))
        proto_port = f"{proto}:{port}" if proto and port else proto or port or ""
        icon = _DIR_ICON.get(direction, "")
        prefix = "🔴 " if f.get("trust_boundary_crossing") else ""
        bits = [x for x in (proto_port, _str(f.get("data"))) if x]
        if f.get("encrypted") is True and "encrypted" not in " ".join(bits):
            bits.append("🔒")
        lbl_inner = ", ".join(bits)
        lbl_parts = [x for x in (prefix, icon, lbl_inner) if x]
        lbl = _mm_label(" ".join(lbl_parts))
        lines.append(f'  {a} -->|"{lbl}"| {b}' if lbl else f"  {a} --> {b}")

    return "\n".join(lines)


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
    _raw_flows = raw.get("data_flows") or []
    data_flows = []
    for _df in _raw_flows[:80]:
        if not isinstance(_df, dict):
            continue
        data_flows.append({
            "from": _str(_df.get("from")),
            "to": _str(_df.get("to")),
            "label": _str(_df.get("label")),
            "is_attack_vector": bool(_df.get("is_attack_vector", False)),
            "protocol": _str(_df.get("protocol")),
            "port": _str(_df.get("port")),
            "data": _str(_df.get("data")),
            "encrypted": bool(_df.get("encrypted", True)),
            "direction": _str(_df.get("direction")) or "internal",
            "trust_boundary_crossing": bool(_df.get("trust_boundary_crossing", False)),
            "exposure": _str(_df.get("exposure")) or "private",
            "authentication_required": bool(_df.get("authentication_required", True)),
            "notes": _str(_df.get("notes")),
        })
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
        likelihood = _clip(t.get("likelihood"), 1, 10, 5)
        impact = _clip(t.get("impact"), 1, 10, 5)
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
    # Always render the diagram deterministically from the structured
    # components + data_flows. LLM-authored Mermaid frequently has syntax
    # errors (e.g. unquoted parens in edge labels like `-->|https (pii)|`)
    # that break the client renderer; building it ourselves from data we
    # control guarantees valid Mermaid.
    dfd = _build_mermaid(components, data_flows)

    # ── Adversary profiles (Phase 9) ──────────────────────────────────────
    adversary_profiles_raw = raw.get("adversary_profiles") or []
    adversary_profiles = []
    for i, ap in enumerate(adversary_profiles_raw[:10], 1):
        if not isinstance(ap, dict):
            continue
        adversary_profiles.append({
            "id": _str(ap.get("id")) or f"AP{i:02d}",
            "name": _str(ap.get("name"), default=f"Threat Actor {i}"),
            "type": _str(ap.get("type")).lower() or "unknown",
            "motivation": _str(ap.get("motivation")) or "unknown",
            "sophistication": _str(ap.get("sophistication")).lower() or "medium",
            "targeted_assets": ap.get("targeted_assets") if isinstance(ap.get("targeted_assets"), list) else [],
            "likely_techniques": ap.get("likely_techniques") if isinstance(ap.get("likely_techniques"), list) else [],
            "threat_ids": ap.get("threat_ids") if isinstance(ap.get("threat_ids"), list) else [],
            "likelihood": _clip(ap.get("likelihood"), 1, 10, 5),
            "rationale": _str(ap.get("rationale")),
        })

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
        "adversary_profiles": adversary_profiles,
    }


def _derive_attack_trees(
    threats: List[Dict[str, Any]],
    components: List[Dict[str, Any]],
    data_flows: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Build attack chain trees from threats.

    Strategy 1 (preferred): blast_radius chaining — follow each threat's
    blast_radius list to find threats on downstream components.

    Strategy 2 (fallback for old models): trust-zone + data-flow adjacency.
    The canonical attack path goes public → dmz → private → data-tier, so
    we chain threats that target components in successive zones, connected by
    a data flow edge.  If no data_flows are available, we rely on zone order
    alone.

    Returns up to 5 distinct attack trees with ≥ 2 steps each.
    """
    import functools

    if not threats:
        return []

    # Index: component_id → [threat]
    comp_to_threats: Dict[str, List[Dict]] = {}
    for t in threats:
        aid = _str(t.get("asset_id"))
        if aid:
            comp_to_threats.setdefault(aid, []).append(t)

    comp_info: Dict[str, Dict] = {_str(c.get("id")): c for c in components if c.get("id")}

    # Data-flow adjacency: component_id → set of reachable component_ids
    flow_adj: Dict[str, set] = {}
    for f in (data_flows or []):
        frm, to = _str(f.get("from")), _str(f.get("to"))
        if frm and to:
            flow_adj.setdefault(frm, set()).add(to)
            if f.get("direction") == "bidirectional":
                flow_adj.setdefault(to, set()).add(frm)

    # Trust zone ordering (lower index = more exposed)
    _ZONE_ORDER = ["public", "dmz", "partner", "private", "management", "data-tier"]

    def _zone_rank(cid: str) -> int:
        zone = _str((comp_info.get(cid) or {}).get("trust_zone")).lower()
        try:
            return _ZONE_ORDER.index(zone)
        except ValueError:
            return 2  # default to middle

    def _find_follow_ons(root_id: str, used_ids: set) -> List[Dict]:
        """Find threats on components reachable from root_id."""
        # Try blast_radius first
        root_threat = next((t for t in threats if t.get("asset_id") == root_id), None)
        blast = (root_threat or {}).get("blast_radius") or []

        candidates: List[str] = []
        if blast:
            candidates = [b for b in blast if b != root_id]
        else:
            # Fallback: data-flow neighbours deeper into the trust zone
            neighbours = flow_adj.get(root_id, set())
            root_rank = _zone_rank(root_id)
            deeper = sorted(
                [n for n in neighbours if _zone_rank(n) > root_rank],
                key=_zone_rank,
            )
            # Also add same-zone neighbours if nothing deeper
            if not deeper:
                deeper = [n for n in neighbours if n != root_id]
            candidates = deeper[:5]

            # If still nothing via flows, pick threats on components in the next zone
            if not candidates:
                root_rank = _zone_rank(root_id)
                next_rank = root_rank + 1
                candidates = [
                    cid for cid in comp_info
                    if _zone_rank(cid) == next_rank and cid != root_id
                ]

        result = []
        for cid in candidates[:5]:
            for ft in comp_to_threats.get(cid, []):
                if ft["id"] not in used_ids:
                    result.append(ft)
                    break  # one threat per downstream component
        return result[:3]

    trees = []
    seen_roots: set = set()

    # Start chains from entry-point-facing threats (internet-exposed / critical)
    sorted_threats = sorted(
        [t for t in threats if t.get("severity") in ("critical", "high")],
        key=lambda t: (_zone_rank(t.get("asset_id", "")), -int(t.get("likelihood") or 5)),
    )

    for root_t in sorted_threats:
        if root_t["id"] in seen_roots:
            continue
        seen_roots.add(root_t["id"])

        used = {root_t["id"]}
        chain_steps = [{
            "step": 1,
            "threat_id": root_t["id"],
            "title": root_t.get("title", ""),
            "severity": root_t.get("severity", ""),
            "likelihood": int(root_t.get("likelihood") or 5),
            "asset_id": root_t.get("asset_id", ""),
        }]

        current_asset = root_t.get("asset_id", "")
        for _ in range(4):  # up to 4 more steps
            follow_ons = _find_follow_ons(current_asset, used)
            if not follow_ons:
                break
            fo = follow_ons[0]
            used.add(fo["id"])
            chain_steps.append({
                "step": len(chain_steps) + 1,
                "threat_id": fo["id"],
                "title": fo.get("title", ""),
                "severity": fo.get("severity", ""),
                "likelihood": int(fo.get("likelihood") or 5),
                "asset_id": fo.get("asset_id", ""),
            })
            current_asset = fo.get("asset_id", "")

        if len(chain_steps) < 2:
            continue

        probs = [s["likelihood"] / 10 for s in chain_steps]
        combined = round(functools.reduce(lambda a, b: a * b, probs, 1.0), 3)

        mitre = list({
            tech
            for step in chain_steps
            for threat_obj in [next((x for x in threats if x["id"] == step["threat_id"]), {})]
            for tech in (threat_obj.get("attack_techniques") or [])
        })

        trees.append({
            "id": f"AT{len(trees)+1:02d}",
            "root_goal": f"Compromise {root_t.get('asset_id', 'system')} → lateral movement to deeper tiers",
            "root_threat_id": root_t["id"],
            "steps": chain_steps,
            "combined_probability": combined,
            "impact": root_t.get("severity", "high"),
            "mitre_chain": mitre,
        })
        if len(trees) >= 5:
            break

    return trees


def _extract_sigma_rules(threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert detection_rule_refs stubs into structured Sigma-like rule dicts."""
    rules = []
    for t in threats:
        for ref in (t.get("detection_rule_refs") or []):
            if not isinstance(ref, dict):
                continue
            rules.append({
                "threat_id": t["id"],
                "threat_title": t.get("title", ""),
                "platform": ref.get("platform", "generic"),
                "rule_id": ref.get("rule_id", ""),
                "severity": t.get("severity", "medium"),
                "status": "advisory",
                "sigma_yaml": (
                    f"title: {t.get('title', 'Detection Rule')}\n"
                    f"status: experimental\n"
                    f"level: {t.get('severity', 'medium')}\n"
                    f"description: Detect {t.get('title', '')} — {t.get('attack_narrative', '')[:200]}\n"
                    f"references:\n"
                    + "".join(f"  - {tech}\n" for tech in (t.get("attack_techniques") or []))
                    + f"logsource:\n  product: {ref.get('platform', 'windows')}\n"
                    f"detection:\n  keywords:\n"
                    + "".join(f"    - '{kw}'\n" for kw in (t.get("cwe_refs") or t.get("capec_refs") or ["*"]))[:3]
                    + "  condition: keywords\n"
                    f"falsepositives:\n  - Legitimate administrative activity\n"
                    f"tags:\n"
                    + "".join(f"  - attack.{tech.lower().replace('-', '_')}\n" for tech in (t.get("attack_techniques") or [])[:3])
                ),
            })
    return rules


# ── LLM call ─────────────────────────────────────────────────────────────────


async def _invoke_llm(
    scope: Dict[str, Any], framework: Optional[str], methodology: str,
    library: Optional[List[Dict[str, Any]]] = None,
    preset_components: Optional[List[Dict[str, Any]]] = None,
    preset_data_flows: Optional[List[Dict[str, Any]]] = None,
    diagram_image: Optional[Dict[str, Any]] = None,
    analyst_notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Call configured LLM. Returns the normalised model. Falls back to a
    deterministic skeleton when no provider is available."""
    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        llm = get_llm(temperature=0.2, max_tokens=THREAT_MODEL_MAX_TOKENS)
    except Exception as exc:
        logger.warning("Threat modeler LLM unavailable, returning skeleton: %s", exc)
        return _skeleton(scope, methodology), {"provider": "fallback", "model": None, "tokens": 0}

    user_prompt = _build_user_prompt(
        scope, framework, methodology, library=library,
        preset_components=preset_components, preset_data_flows=preset_data_flows,
        analyst_notes=analyst_notes,
    )

    # When an uploaded diagram image is available, attach it so a vision model
    # threat-models from the actual picture, not just the extracted component
    # list. Built as a multimodal HumanMessage; falls back to text-only if the
    # provider/model can't accept images.
    text_message = lambda: [
        SystemMessage(content=_build_system_prompt(methodology)),
        HumanMessage(content=user_prompt),
    ]
    messages = text_message()
    if diagram_image and diagram_image.get("b64"):
        data_uri = f"data:{diagram_image.get('mime', 'image/png')};base64,{diagram_image['b64']}"
        messages = [
            SystemMessage(content=_build_system_prompt(methodology)),
            HumanMessage(content=[
                {"type": "text", "text": user_prompt + (
                    "\n\nThe customer's architecture diagram is attached as an image. "
                    "Treat it as authoritative: validate and enrich the listed components, "
                    "trace data flows and trust boundaries you can see, and flag exposed "
                    "entry points — then identify threats grounded in that diagram."
                )},
                {"type": "image_url", "image_url": {"url": data_uri}},
            ]),
        ]

    try:
        # Bound the call so a stalled provider connection can't leave the
        # threat model wedged in 'generating' forever.
        result = await asyncio.wait_for(llm.ainvoke(messages), timeout=LLM_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning("Threat modeler LLM call timed out after %ss", LLM_TIMEOUT_SECONDS)
        return _skeleton(scope, methodology), {"provider": "fallback", "model": None, "tokens": 0,
                                               "error": f"LLM call timed out after {LLM_TIMEOUT_SECONDS}s"}
    except Exception as exc:
        # A vision-incapable provider rejects the image part — retry text-only.
        if diagram_image and diagram_image.get("b64"):
            logger.warning("Vision call failed (%s); retrying text-only", type(exc).__name__)
            try:
                result = await asyncio.wait_for(llm.ainvoke(text_message()), timeout=LLM_TIMEOUT_SECONDS)
            except Exception as exc2:
                logger.exception("Threat modeler LLM call failed (after vision fallback)")
                return _skeleton(scope, methodology), {"provider": "fallback", "model": None, "tokens": 0,
                                                       "error": f"{type(exc2).__name__}: {exc2}"}
        else:
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

    # finish_reason='length' means the model hit the output-token cap before
    # finishing — the JSON is truncated and won't parse.
    finish = ""
    try:
        finish = (getattr(result, "response_metadata", None) or {}).get("finish_reason", "") or ""
    except Exception:
        finish = ""

    parse_error: Optional[str] = None
    try:
        # Find first { ... last }
        start = text.find("{")
        end = text.rfind("}")
        parsed = json.loads(text[start:end + 1]) if start >= 0 and end > start else {}
        if not parsed:
            parse_error = "no JSON object found in response"
    except Exception as exc:
        parse_error = str(exc)
        logger.warning("Threat modeler JSON parse failed (finish=%s, %d chars): %s | head=%r",
                       finish, len(text), exc, text[:300])
        parsed = {}

    usage = getattr(result, "usage_metadata", None) or {}
    meta: Dict[str, Any] = {
        "provider": "configured",  # core.ai_providers picks the actual provider
        "model": getattr(llm, "model_name", None) or getattr(llm, "model", None),
        "tokens": int(usage.get("total_tokens") or 0),
    }
    if parse_error:
        if finish == "length":
            meta["error"] = ("The model's response was truncated at the output-token limit before "
                             "the JSON was complete. The output cap has been raised — please rescan.")
        else:
            meta["error"] = f"The model's response could not be parsed as JSON ({parse_error})."
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


# ── Stepped generation pipeline (live progress for the UI) ───────────────────

# (key, label) — label may use {methodology} which is filled in per-run.
_PIPELINE: List[Tuple[str, str]] = [
    ("assets",   "Discover assets in scope"),
    ("context",  "Gather findings & risk assessment"),
    ("library",  "Load CAPEC / ATT&CK threat library"),
    ("model",    "Run {methodology} threat analysis"),
    ("finalize", "Finalize model & score coverage"),
]


def _init_progress(methodology_label: str) -> Dict[str, Any]:
    return {
        "current": "Starting…",
        "pct": 0,
        "steps": [
            {"key": k, "label": lbl.format(methodology=methodology_label),
             "status": "pending", "detail": ""}
            for k, lbl in _PIPELINE
        ],
    }


def _set_step(db: Session, tm: ThreatModel, key: str, status: str, detail: str = "") -> None:
    """Update one pipeline step and commit so the polling detail endpoint
    reflects it in near-real-time. Best-effort — never raises out."""
    from sqlalchemy.orm.attributes import flag_modified
    try:
        prog = dict(tm.progress_json or {})
        steps = [dict(s) for s in (prog.get("steps") or [])]
        for s in steps:
            if s.get("key") == key:
                s["status"] = status
                if detail:
                    s["detail"] = detail
                prog["current"] = s.get("label", "") + (f" — {detail}" if detail else "")
        n = len(steps) or 1
        done = sum(1 for s in steps if s.get("status") in ("done", "skipped"))
        active = sum(1 for s in steps if s.get("status") == "active")
        prog["pct"] = int(min(99, round(100 * (done + 0.5 * active) / n)))
        prog["steps"] = steps
        tm.progress_json = prog
        flag_modified(tm, "progress_json")  # in-place dict mutations aren't auto-tracked
        db.commit()
    except Exception:
        logger.exception("progress update failed (continuing)")
        db.rollback()


def _scope_asset_count(db: Session, tm: ThreatModel) -> int:
    q = db.query(Asset).filter(Asset.client_id == tm.client_id)
    scan_ids = [s for s in (tm.scope_scan_ids or []) if s]
    if tm.scope_type == "asset" and tm.scope_id:
        q = q.filter(Asset.id == tm.scope_id)
        return q.count()
    q = q.filter(Asset.status == AssetStatus.ACTIVE.value)
    q = q.filter(Asset.asset_class.isnot(None), Asset.asset_class != "", Asset.asset_class != "other")
    if scan_ids:
        conn_ids = [cid for (cid,) in db.query(Scan.connector_id).filter(Scan.id.in_(scan_ids)).all() if cid]
        if conn_ids:
            q = q.filter(Asset.connector_id.in_(conn_ids))
    elif tm.scope_type == "project" and tm.scope_id:
        q = q.filter(Asset.project_id == tm.scope_id)
    return q.count()


async def _ensure_assets(db: Session, tm: ThreatModel) -> int:
    """Make sure the scope has assets to model. If it's empty but the client
    has connectors, sync them one connector at a time (best-effort, with live
    progress) so the model is built from real inventory rather than guesses."""
    have = _scope_asset_count(db, tm)
    if have > 0:
        _set_step(db, tm, "assets", "done", f"{have} assets already in scope")
        return have

    connectors = db.query(Connector).filter(Connector.client_id == tm.client_id).all()
    if not connectors:
        _set_step(db, tm, "assets", "skipped", "no assets or connectors — modelling from architecture")
        return 0

    from connectors.sync import sync_connector_assets
    total_new = 0
    for c in connectors:
        cname = c.name or (c.connector_type.value if hasattr(c.connector_type, "value") else str(c.connector_type))
        _set_step(db, tm, "assets", "active", f"syncing from {cname}…")
        try:
            created, _updated, _stale = await sync_connector_assets(db, c)
            db.commit()
            total_new += created
        except Exception as exc:
            logger.warning("asset sync failed for connector %s: %s", c.id, exc)
            db.rollback()
    have = _scope_asset_count(db, tm)
    if have:
        _set_step(db, tm, "assets", "done", f"{have} assets discovered ({total_new} new)")
    else:
        _set_step(db, tm, "assets", "skipped", "connectors returned no assets — modelling from architecture")
    return have


async def generate_threat_model(db: Session, model_id: str) -> ThreatModel:
    """Run the modeler against a ThreatModel row that's already persisted in
    `pending` state, as a visible multi-step pipeline. Updates the row in
    place with normalised output and per-step progress, sets status to
    `completed` / `failed`."""
    from sqlalchemy.orm.attributes import flag_modified
    tm = db.query(ThreatModel).filter(ThreatModel.id == model_id).first()
    if not tm:
        raise ValueError(f"ThreatModel {model_id} not found")
    methodology = (tm.methodology or DEFAULT_METHODOLOGY).lower()
    if methodology not in METHODOLOGIES:
        methodology = DEFAULT_METHODOLOGY
    label = METHODOLOGIES[methodology]["label"]
    tm.status = "generating"
    tm.error_message = None
    tm.progress_json = _init_progress(label)
    flag_modified(tm, "progress_json")
    db.commit()

    try:
        # Architecture source:
        #  - diagram upload (scope_type 'diagram') → user-reviewed components
        #  - components_pinned → analyst-curated set (edit & re-model)
        #  - else → derive deterministically from the scoped assets
        orig_components = tm.components_json or None
        orig_data_flows = tm.data_flows_json or None
        is_diagram = (tm.scope_type == "diagram")
        use_pinned = bool(orig_components) and (is_diagram or bool(tm.components_pinned))
        pinned = orig_components if use_pinned else None

        # Step 1 — assets
        if pinned:
            src = "uploaded diagram" if is_diagram else "analyst-curated set"
            _set_step(db, tm, "assets", "done", f"{len(pinned)} components from {src}")
        else:
            await _ensure_assets(db, tm)

        # Step 2 — context (assets + findings + risk register + connectors)
        _set_step(db, tm, "context", "active")
        scope = _collect_scope(db, tm.client_id, tm.scope_type or "client", tm.scope_id,
                               scan_ids=tm.scope_scan_ids)
        _set_step(db, tm, "context", "done",
                  f"{scope['asset_count']} assets · {scope['finding_count']} findings · "
                  f"{scope.get('risk_count', 0)} risks")

        # When not pinned, derive components deterministically from the scoped
        # assets (consistent across methodologies / reruns); fall back to
        # LLM-invented architecture only when there are no assets at all.
        derived_components = None if (pinned or is_diagram) else (_components_from_assets(scope.get("assets")) or None)
        pinned_components = pinned or derived_components

        fw = tm.framework.value if hasattr(tm.framework, "value") else (tm.framework or None)

        # Step 3 — threat library
        _set_step(db, tm, "library", "active")
        library = _library_sample(db, methodology)
        _set_step(db, tm, "library", "done", f"{len(library)} reference patterns")

        # Step 4 — LLM analysis (architecture pinned when we have one, so the
        # LLM keys threats/flows to those exact component IDs).
        _set_step(db, tm, "model", "active", f"calling {label} model")
        model, meta = await _invoke_llm(
            scope, fw, methodology, library=library,
            preset_components=pinned_components, preset_data_flows=orig_data_flows,
            diagram_image=tm.source_diagram, analyst_notes=tm.analyst_notes,
        )
        threats_out = model.get("threats") or []
        has_arch = bool(pinned_components or model.get("components"))
        if not has_arch and not threats_out:
            reason = meta.get("error") or "The model returned an empty threat model. Please rescan."
            _set_step(db, tm, "model", "error", reason)
            raise RuntimeError(reason)
        _set_step(db, tm, "model", "done", f"{len(threats_out)} threats identified")

        # Step 5 — finalize the architecture.
        _set_step(db, tm, "finalize", "active")
        if is_diagram and use_pinned:
            # Uploaded diagram: components AND the user-reviewed flows are authoritative.
            tm.components_json = pinned
            tm.data_flows_json = orig_data_flows or []
        elif pinned_components:
            # Asset-derived or analyst-curated component set.
            # Append LLM-generated threat actors — they are always synthetic
            # (never in the asset inventory) so they must come from the LLM.
            # All real-asset components keep their deterministic IDs.
            pinned_ids = {c["id"] for c in pinned_components}
            threat_actors = [
                c for c in (model.get("components") or [])
                if c.get("is_threat_actor") and _str(c.get("id")) not in pinned_ids
            ]
            merged = pinned_components + threat_actors
            known = {c["id"] for c in merged}
            tm.components_json = merged
            tm.data_flows_json = [
                f for f in (model.get("data_flows") or [])
                if _str(f.get("from")) in known and _str(f.get("to")) in known
            ]
        else:
            # No assets in scope — the LLM's inferred architecture stands.
            tm.components_json = model.get("components") or []
            tm.data_flows_json = model.get("data_flows") or []
        tm.threats_json = model["threats"]
        tm.mitigations_json = model["mitigations"]
        # Rebuild the diagram from the FINAL (pinned) components/flows so it
        # matches the stored architecture rather than the LLM's raw component set.
        tm.dfd_mermaid = _build_mermaid(tm.components_json or [], tm.data_flows_json or [])
        tm.executive_summary = model["executive_summary"]
        # Phase 8 — persist the completeness + coverage fields.
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
        # Phase 9 — adversary profiles
        tm.adversary_profiles_json = model.get("adversary_profiles") or []
        # Phase 9 — attack trees (derived from blast_radius chaining)
        try:
            tm.attack_trees_json = _derive_attack_trees(
                model.get("threats") or [], model.get("components") or [],
                data_flows=model.get("data_flows") or [],
            )
        except Exception:
            logger.exception("attack tree derivation failed (continuing)")
            tm.attack_trees_json = []
        # Phase 9 — Sigma rule stubs
        try:
            tm.sigma_rules_json = _extract_sigma_rules(model.get("threats") or [])
        except Exception:
            logger.exception("sigma rule extraction failed (continuing)")
            tm.sigma_rules_json = []
        tm.ai_provider = meta.get("provider")
        tm.ai_model = meta.get("model")
        tm.tokens_used = int(meta.get("tokens") or 0)
        _set_step(db, tm, "finalize", "done", "model ready")

        prog = dict(tm.progress_json or {})
        prog["pct"] = 100
        prog["current"] = "Completed"
        tm.progress_json = prog
        flag_modified(tm, "progress_json")
        tm.status = "completed"
        tm.generated_at = datetime.now(timezone.utc)
        if meta.get("error"):
            tm.error_message = meta["error"]
        # Phase 9 — seed Risk register from high/critical threat model threats
        try:
            from api.models.models import Risk, RiskLevel
            existing_titles = {r.title for r in db.query(Risk).filter(
                Risk.client_id == tm.client_id, Risk.status == "open"
            ).all()}
            for threat in (tm.threats_json or []):
                if threat.get("severity") not in ("critical", "high"):
                    continue
                title = f"[TM] {threat.get('title', '')}"[:500]
                if title in existing_titles:
                    continue
                lh = int(threat.get("likelihood") or 5)
                imp = int(threat.get("impact") or 5)
                rl = RiskLevel.CRITICAL if threat.get("severity") == "critical" else RiskLevel.HIGH
                db.add(Risk(
                    client_id=tm.client_id,
                    title=title,
                    description=(
                        f"Source: Threat Model — {tm.name or tm.id}\n\n"
                        f"{threat.get('rationale', '')}"
                    ),
                    risk_level=rl,
                    likelihood=lh,
                    impact=imp,
                    risk_score=round(lh * imp / 10, 1),
                    category=threat.get("category", "threat_model"),
                    status="open",
                    finding_ids=[],
                ))
                existing_titles.add(title)
        except Exception:
            logger.exception("Risk seeding from threat model failed (continuing)")
        db.commit()
        db.refresh(tm)
        return tm
    except Exception as exc:
        logger.exception("Threat model generation failed for %s", model_id)
        tm.status = "failed"
        tm.error_message = f"{type(exc).__name__}: {exc}"
        tm.generated_at = datetime.now(timezone.utc)
        try:
            prog = dict(tm.progress_json or {})
            for s in prog.get("steps") or []:
                if s.get("status") == "active":
                    s["status"] = "error"
            prog["current"] = "Failed"
            tm.progress_json = prog
            flag_modified(tm, "progress_json")
        except Exception:
            pass
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
