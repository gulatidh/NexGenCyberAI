"""Generate the structured report attached to every workflow (mission) run.

Goal: same report shape every time, so the UI renders identically and the
PDF export looks like a real deliverable. The LLM gets a strict prompt
that names the section list and forbids extra keys; we then validate and
fall back to a deterministic skeleton on any failure.

Standard report schema (every run has the same shape):

    {
      "schema_version": 1,
      "generated_at": <iso>,
      "model": <provider/model used>,
      "mission_type": <enum value>,
      "mission_type_label": <human label>,
      "client_id": <uuid>,
      "client_name": <name>,
      "title": "<Mission> — <Client> — <YYYY-MM-DD>",
      "subtitle": <one-line context line>,
      "metrics": [{"label": "...", "value": "...", "tone": "neutral|good|warn|bad"}, ...],
      "sections": [
        {"id": "executive_summary",    "title": "Executive Summary",     "body": "<markdown>"},
        {"id": "scope_and_inputs",     "title": "Scope & Inputs",        "body": "<markdown>"},
        {"id": "key_findings",         "title": "Key Findings",          "body": "<markdown>"},
        {"id": "risk_picture",         "title": "Risk Picture",          "body": "<markdown>"},
        {"id": "recommendations",      "title": "Recommendations",       "body": "<markdown>"},
        {"id": "next_steps",           "title": "Next Steps (30/60/90)", "body": "<markdown>"},
        {"id": "data_completeness",    "title": "Data Completeness",     "body": "<markdown>"}
      ]
    }
"""
from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import desc

from api.models.models import (
    Client, Connector, Finding, MissionType, Risk, Scan, ScheduledMission,
    ScheduledMissionRun,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

# Fixed section order — never changes regardless of mission_type so reports
# look like the same template every time.
STANDARD_SECTIONS = [
    ("executive_summary", "Executive Summary"),
    ("scope_and_inputs", "Scope & Inputs"),
    ("key_findings", "Key Findings"),
    ("risk_picture", "Risk Picture"),
    ("recommendations", "Recommendations"),
    ("next_steps", "Next Steps (30 / 60 / 90 days)"),
    ("data_completeness", "Data Completeness"),
]


MISSION_TYPE_LABEL = {
    MissionType.SOC_DESIGN: "SOC Design",
    MissionType.VULNERABILITY_RESPONSE: "Vulnerability Response",
    MissionType.GRC_ADVISORY: "GRC Advisory",
    MissionType.CLOUD_SECURITY_ASSESSMENT: "Cloud Security Assessment",
    MissionType.ZERO_TRUST_DESIGN: "Zero Trust Design",
    MissionType.INCIDENT_RESPONSE_PROGRAM: "Incident Response Program",
    MissionType.THREAT_INTEL_PROGRAM: "Threat Intelligence Program",
    MissionType.DATA_PROTECTION_ASSESSMENT: "Data Protection Assessment",
    MissionType.IGA_DEPLOYMENT: "IGA Deployment",
    MissionType.PHISHING_TRIAGE: "Phishing Triage",
    MissionType.PORTFOLIO_RATIONALIZATION: "Portfolio Rationalization",
    MissionType.SECURITY_ARCHITECTURE_REVIEW: "Security Architecture Review",
}

# Per-mission-type guidance — injected into the LLM prompt so each report
# is specialised while still using the same section list. Keep these short
# and focused; the LLM gets the canonical section names + this guidance.
MISSION_GUIDANCE: Dict[MissionType, str] = {
    MissionType.CLOUD_SECURITY_ASSESSMENT: (
        "Audience: CISO + cloud platform leadership. Emphasize CSPM / CWPP / CIEM "
        "posture, shared-responsibility gaps, and IAM blast radius. Cite CIS "
        "Foundations Benchmarks (Azure / AWS / GCP) where relevant."
    ),
    MissionType.SOC_DESIGN: (
        "Audience: SOC director + MSSP buyer. Compare in-house vs co-managed vs "
        "fully-managed models on coverage, MTTD/MTTR, and cost. Reference NIST 800-61."
    ),
    MissionType.VULNERABILITY_RESPONSE: (
        "Audience: vulnerability management lead + asset owners. Surface CVE backlog, "
        "SLA compliance, exception ratios, and patch throughput. Recommend a tiered "
        "SLA model (Critical 7d / High 30d / Medium 90d)."
    ),
    MissionType.GRC_ADVISORY: (
        "Audience: Chief Compliance Officer + audit committee. Map control gaps across "
        "applicable frameworks (NIST CSF, NIST 800-53, ISO 27001, SOC 2, PCI DSS, CMMC). "
        "Quantify audit readiness."
    ),
    MissionType.ZERO_TRUST_DESIGN: (
        "Audience: enterprise architect + identity lead. Sequence ZT roadmap by NIST "
        "SP 800-207 + CISA Zero Trust Maturity Model across identity, device, network, "
        "application, and data pillars."
    ),
    MissionType.INCIDENT_RESPONSE_PROGRAM: (
        "Audience: CISO + IR retainer owner. Score IR maturity against NIST SP 800-61 "
        "(Prepare → Detect → Contain → Eradicate → Recover → Lessons Learned). "
        "Identify retainer + tabletop needs."
    ),
    MissionType.THREAT_INTEL_PROGRAM: (
        "Audience: threat intel manager + SOC head. Cover collection (commercial + OSS + "
        "industry-sharing), analysis, dissemination cadence, and intel-driven detection "
        "engineering."
    ),
    MissionType.DATA_PROTECTION_ASSESSMENT: (
        "Audience: DPO + privacy counsel. Span GDPR, CCPA, and applicable sectoral laws "
        "(HIPAA / GLBA / PCI). Cover classification, DLP, encryption-in-transit / at-rest, "
        "and cross-border transfer mechanisms."
    ),
    MissionType.IGA_DEPLOYMENT: (
        "Audience: IAM lead + control owners. Cover joiner/mover/leaver automation, "
        "access reviews, role mining, segregation of duties (SoD), and target-system "
        "provisioning."
    ),
    MissionType.PHISHING_TRIAGE: (
        "Audience: SOC analyst lead + awareness program owner. Cover reported-email "
        "triage workflow, IOC extraction, sandbox detonation, and tuning the awareness "
        "program based on click rates."
    ),
    MissionType.PORTFOLIO_RATIONALIZATION: (
        "Audience: CISO + procurement. Cluster the security tool stack by capability "
        "(CNAPP, SIEM, EDR, IAM, etc.), flag overlaps, and recommend consolidations "
        "with quantified savings."
    ),
    MissionType.SECURITY_ARCHITECTURE_REVIEW: (
        "Audience: enterprise security architect + CTO. Map the reference architecture "
        "across identity, network, endpoint, cloud, and data layers. Identify "
        "single-points-of-failure and missing controls."
    ),
}


# ── Context gathering ────────────────────────────────────────────────────────


def _client_context(db: Session, client_id: str) -> Dict[str, Any]:
    """What we know about a client — name + connector + scan + risk counts."""
    c = db.query(Client).filter(Client.id == client_id).first()
    name = c.name if c else "Unknown Client"
    industry = c.industry if c else None
    country = c.country if c else None

    connector_count = db.query(Connector).filter(Connector.client_id == client_id).count()
    scan_count = db.query(Scan).filter(Scan.client_id == client_id).count()

    recent_scans = (
        db.query(Scan).filter(Scan.client_id == client_id)
        .order_by(desc(Scan.created_at)).limit(5).all()
    )
    scan_summaries = [
        {
            "id": s.id,
            "scan_type": s.scan_type.value if hasattr(s.scan_type, "value") else str(s.scan_type),
            "status": s.status.value if hasattr(s.status, "value") else str(s.status),
            "summary": s.summary or {},
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in recent_scans
    ]

    # Severity rollup across this client's findings
    sev_counts: Dict[str, int] = {}
    rows = (
        db.query(Finding.severity, Finding.id)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id)
        .all()
    )
    for sev, _id in rows:
        v = sev.value if hasattr(sev, "value") else str(sev)
        sev_counts[v] = sev_counts.get(v, 0) + 1

    # Risk breakdown
    risk_counts: Dict[str, int] = {}
    for r in db.query(Risk).filter(Risk.client_id == client_id).all():
        lv = r.risk_level.value if hasattr(r.risk_level, "value") else str(r.risk_level)
        risk_counts[lv] = risk_counts.get(lv, 0) + 1

    return {
        "client_name": name,
        "industry": industry,
        "country": country,
        "connector_count": connector_count,
        "scan_count": scan_count,
        "finding_severity_counts": sev_counts,
        "risk_level_counts": risk_counts,
        "recent_scans": scan_summaries,
    }


def _mission_type_value(m: ScheduledMission) -> str:
    mt = m.mission_type
    return mt.value if hasattr(mt, "value") else str(mt)


def _metrics_from_context(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    sev = ctx.get("finding_severity_counts") or {}
    risks = ctx.get("risk_level_counts") or {}
    crit_sev = sev.get("critical", 0)
    crit_risk = risks.get("critical", 0)
    high_risk = risks.get("high", 0)
    return [
        {"label": "Connectors",         "value": str(ctx.get("connector_count", 0)),                       "tone": "neutral"},
        {"label": "Scans on record",    "value": str(ctx.get("scan_count", 0)),                            "tone": "neutral"},
        {"label": "Critical findings",  "value": str(crit_sev),                                             "tone": "bad" if crit_sev else "good"},
        {"label": "Critical / High risks", "value": f"{crit_risk} / {high_risk}",                          "tone": "bad" if (crit_risk + high_risk) else "good"},
    ]


# ── Prompt construction ─────────────────────────────────────────────────────


_SYSTEM_PROMPT = (
    "You author standardised security advisory reports. You ALWAYS return strict "
    "JSON matching the requested schema — no markdown fences, no preamble, no "
    "trailing commentary. Each section body is concise, senior-level markdown "
    "(use ## sub-headings, - bullets, **bold**, tables where useful). Avoid "
    "fabricating tool names, control IDs, vendor names, or numbers — if the "
    "evidence is missing, write that the data is unavailable and recommend "
    "next steps. Reports must read the same way every time: same sections, "
    "same order, same tone (calm, executive, audit-grade)."
)


def _user_prompt(
    *, mission: ScheduledMission, ctx: Dict[str, Any], guidance: str,
) -> str:
    section_list = "\n".join(f"  - {sid}: {title}" for sid, title in STANDARD_SECTIONS)
    mt_value = _mission_type_value(mission)
    return (
        f"# Mission type\n{mt_value} — {MISSION_TYPE_LABEL.get(mission.mission_type, mt_value)}\n\n"
        f"# Audience and focus\n{guidance}\n\n"
        f"# Client context (the only evidence; do not invent data outside this)\n"
        f"```json\n{json.dumps(ctx, indent=2, default=str)}\n```\n\n"
        f"# Required output JSON\nReturn a single JSON object with these keys:\n"
        f"  - title: '<MissionLabel> — <ClientName> — <YYYY-MM-DD>'\n"
        f"  - subtitle: one-line scope statement (≤140 chars)\n"
        f"  - sections: an array of objects, EXACTLY these 7 ids in this order:\n{section_list}\n\n"
        f"Each section is {{ id, title, body }}. The body is markdown.\n"
        f"Do not include any keys other than the ones listed."
    )


# ── Skeleton fallback (no LLM available) ────────────────────────────────────


def _skeleton(mission: ScheduledMission, ctx: Dict[str, Any]) -> Dict[str, Any]:
    label = MISSION_TYPE_LABEL.get(mission.mission_type, _mission_type_value(mission))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sev = ctx.get("finding_severity_counts") or {}
    risks = ctx.get("risk_level_counts") or {}
    crit_sev = sev.get("critical", 0)
    high_sev = sev.get("high", 0)
    sections = [
        {
            "id": "executive_summary",
            "title": "Executive Summary",
            "body": (
                f"This {label} report covers **{ctx.get('client_name', 'the client')}** as of {today}. "
                f"The client environment shows **{ctx.get('connector_count', 0)} configured connector(s)** and "
                f"**{ctx.get('scan_count', 0)} scan(s) on record**. Severity rollup: "
                f"{crit_sev} critical, {high_sev} high. No AI provider was reachable when this report was "
                f"generated, so the narrative below is a deterministic skeleton derived from platform "
                f"telemetry — connect an LLM provider in **AI Settings** for the full advisory."
            ),
        },
        {
            "id": "scope_and_inputs",
            "title": "Scope & Inputs",
            "body": (
                f"- **Mission type:** {label}\n"
                f"- **Client:** {ctx.get('client_name', 'Unknown')}\n"
                f"- **Industry / Country:** {ctx.get('industry') or '—'} / {ctx.get('country') or '—'}\n"
                f"- **Connectors:** {ctx.get('connector_count', 0)}\n"
                f"- **Recent scans:** {len(ctx.get('recent_scans') or [])}"
            ),
        },
        {
            "id": "key_findings",
            "title": "Key Findings",
            "body": (
                f"- {crit_sev} critical finding(s) currently open across recent scans.\n"
                f"- {high_sev} high-severity finding(s) require remediation within SLA.\n"
                f"- {sum(risks.values())} risk record(s) in the register "
                f"({risks.get('critical', 0)} critical, {risks.get('high', 0)} high)."
            ),
        },
        {
            "id": "risk_picture",
            "title": "Risk Picture",
            "body": (
                "Without an active LLM provider this section reports raw counts only. "
                "Configure a provider in AI Settings for FAIR-lite quantification, "
                "domain rollups, and 30-day breach probability narratives."
            ),
        },
        {
            "id": "recommendations",
            "title": "Recommendations",
            "body": (
                "1. Connect an AI provider so future reports include narrative analysis.\n"
                f"2. Triage open critical findings within 24 hours (current backlog: {crit_sev}).\n"
                "3. Codify remediation SLAs (Critical 7d / High 30d / Medium 90d).\n"
                "4. Schedule this workflow on a recurring cadence so trend data accumulates."
            ),
        },
        {
            "id": "next_steps",
            "title": "Next Steps (30 / 60 / 90 days)",
            "body": (
                "- **30 days:** Configure an AI provider; close all critical findings; baseline KPIs.\n"
                "- **60 days:** Run the next scheduled execution of this workflow; review trend.\n"
                "- **90 days:** Quarterly review of SLA compliance + program maturity."
            ),
        },
        {
            "id": "data_completeness",
            "title": "Data Completeness",
            "body": (
                "**Evidenced data sources:**\n"
                f"- Connector inventory: {ctx.get('connector_count', 0)}\n"
                f"- Scan history: {ctx.get('scan_count', 0)} scans\n"
                f"- Finding telemetry: {sum(sev.values())} findings\n"
                f"- Risk register: {sum(risks.values())} risks\n\n"
                "**Estimated:** none in this skeleton.\n"
                "**Unknown:** narrative analysis (requires LLM provider)."
            ),
        },
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": "deterministic-skeleton",
        "mission_type": _mission_type_value(mission),
        "mission_type_label": label,
        "client_id": mission.client_id,
        "client_name": ctx.get("client_name", "Unknown Client"),
        "title": f"{label} — {ctx.get('client_name', 'Unknown')} — {today}",
        "subtitle": "Deterministic skeleton — no AI provider was reachable at generation time.",
        "metrics": _metrics_from_context(ctx),
        "sections": sections,
    }


# ── LLM call + validation ────────────────────────────────────────────────────


def _normalise_sections(sections_in: Any) -> List[Dict[str, Any]]:
    """Force the LLM-returned sections into our fixed 7-section order, drop
    extras, fill missing with empty bodies."""
    by_id: Dict[str, Dict[str, Any]] = {}
    if isinstance(sections_in, list):
        for s in sections_in:
            if isinstance(s, dict) and "id" in s:
                by_id[str(s["id"])] = {
                    "id": str(s["id"]),
                    "title": str(s.get("title") or s["id"].replace("_", " ").title()),
                    "body": str(s.get("body") or ""),
                }
    out: List[Dict[str, Any]] = []
    for sid, default_title in STANDARD_SECTIONS:
        if sid in by_id:
            sec = by_id[sid]
            sec["title"] = default_title  # enforce canonical title for consistency
            out.append(sec)
        else:
            out.append({"id": sid, "title": default_title, "body": "_Section not produced by the model; rerun the workflow for a full report._"})
    return out


async def _llm_generate(mission: ScheduledMission, ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Call the configured LLM. Returns None on failure (caller falls back)."""
    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        guidance = MISSION_GUIDANCE.get(
            mission.mission_type,
            "Audience: senior security leadership. Be concise, evidence-anchored, audit-grade.",
        )
        llm = get_llm(temperature=0.2, max_tokens=3500)
        messages = [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=_user_prompt(mission=mission, ctx=ctx, guidance=guidance)),
        ]
        result = await llm.ainvoke(messages)
        text = result.content if hasattr(result, "content") else str(result)
        if isinstance(text, list):
            text = "\n".join(str(p) for p in text)
        # Strip markdown fences if the model wrapped JSON in them
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            logger.warning("LLM mission report: no JSON object in response")
            return None
        data = json.loads(text[start:end + 1])
        if not isinstance(data, dict):
            return None
        return data
    except Exception as exc:
        logger.warning("LLM mission report generation failed: %s", exc)
        return None


# ── Public entry point ──────────────────────────────────────────────────────


async def generate_report(db: Session, mission: ScheduledMission, run: ScheduledMissionRun) -> Dict[str, Any]:
    """Build the structured report and attach it to the run.

    Same code path whether the run was scheduled or triggered manually —
    we always gather context, always call the LLM, always fall back to the
    skeleton on failure. The result is always the SAME shape so the UI
    renders identically across runs."""
    ctx = _client_context(db, mission.client_id)
    label = MISSION_TYPE_LABEL.get(mission.mission_type, _mission_type_value(mission))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    llm_data = await _llm_generate(mission, ctx)

    if llm_data is None:
        report = _skeleton(mission, ctx)
    else:
        report = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model": str(llm_data.get("model") or "llm"),
            "mission_type": _mission_type_value(mission),
            "mission_type_label": label,
            "client_id": mission.client_id,
            "client_name": ctx.get("client_name", "Unknown Client"),
            "title": str(llm_data.get("title") or f"{label} — {ctx.get('client_name', 'Unknown')} — {today}"),
            "subtitle": str(llm_data.get("subtitle") or "")[:300],
            "metrics": _metrics_from_context(ctx),
            "sections": _normalise_sections(llm_data.get("sections")),
        }

    run.report = report
    db.flush()
    return report
