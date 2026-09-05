"""Wizard-driven audit agents — control testing, readiness reports, evidence curation, interview prep."""
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, distinct
from sqlalchemy.orm import Session, sessionmaker

from api.models.models import (
    AuditAgentRun, ControlDeficiency, Finding, FrameworkControl, RemediationAction, Risk, Scan,
)
from core.ai_providers import get_llm
from core.config import get_settings
from core.security import get_current_user
from db.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(tags=["audit-agents"])

settings = get_settings()

_DOMAIN_TOPIC_KEYWORDS: Dict[str, List[str]] = {
    "Access Control & Identity": ["access", "identity", "privilege", "auth", "mfa", "password", "account", "iam", "role"],
    "Incident Response": ["incident", "response", "breach", "detection", "alert", "soc", "forensic"],
    "Data Protection & Privacy": ["data", "privacy", "gdpr", "encrypt", "pii", "sensitive", "retention", "classification"],
    "Network & Infrastructure": ["network", "firewall", "port", "infrastructure", "tls", "ssl", "vpn", "segmentation"],
    "Change Management": ["change", "patch", "update", "deployment", "release", "configuration", "baseline"],
    "Business Continuity": ["continuity", "disaster", "backup", "recovery", "rto", "rpo", "resilience"],
    "Vulnerability Management": ["vulnerability", "cve", "patch", "scan", "remediat", "exploit", "cvss"],
    "Audit Logging & Monitoring": ["log", "audit", "monitor", "siem", "event", "trail", "alert"],
    "Third-Party Risk": ["third", "vendor", "supplier", "partner", "outsourc", "due diligence"],
    "Cloud Security": ["cloud", "azure", "aws", "gcp", "s3", "storage", "iam", "misconfigur"],
}


def _strip_json(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _parse_llm_json(text: str) -> Any:
    try:
        return json.loads(_strip_json(text))
    except json.JSONDecodeError:
        return {"raw": text}


def _get_session(db_url: str) -> Session:
    engine = create_engine(
        db_url,
        pool_pre_ping=True,
        connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
    )
    return sessionmaker(bind=engine)()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _load_raw_context(db: Session, scan_id: str, max_chars: int = 8000) -> str:
    """Load raw_context from a scan, truncated to fit in an LLM prompt."""
    if not scan_id:
        return ""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or not scan.raw_context:
        return ""
    raw = scan.raw_context
    if len(raw) > max_chars:
        raw = raw[:max_chars] + f"\n... [truncated — full context is {len(scan.raw_context)} chars]"
    return raw


def _build_evidence_map(db: Session, client_id: str, framework: str, scan_id: str = "") -> Dict[str, List[str]]:
    """Maps control_id → list of finding title+severity strings for a given framework."""
    evidence: Dict[str, List[str]] = {}

    findings_q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open")
    )
    if scan_id:
        findings_q = findings_q.filter(Finding.scan_id == scan_id)
    findings = findings_q.all()
    for f in findings:
        tag = f"{f.title} [{f.severity}]"
        if f.control_id and str(getattr(f, "framework", "") or "") == framework:
            evidence.setdefault(f.control_id, []).append(tag)
        mappings = f.control_mappings or {}
        for cids in (mappings.get(framework) or []):
            evidence.setdefault(cids, []).append(tag)

    deficiencies = (
        db.query(ControlDeficiency)
        .filter(ControlDeficiency.client_id == client_id, ControlDeficiency.framework == framework)
        .all()
    )
    for d in deficiencies:
        if d.control_id:
            evidence.setdefault(d.control_id, []).append(f"[GAP] {d.title}")

    return evidence


def _date_range_days(label: str) -> int:
    mapping = {"Last 30 days": 30, "Last 90 days": 90, "Last 6 months": 180, "Last 12 months": 365}
    return mapping.get(label, 90)


# ── Background agent runners ───────────────────────────────────────────────────

def _run_agent(run_id: str, db_url: str, client_id: str, agent_type: str, wizard_inputs: Dict) -> None:
    db = _get_session(db_url)
    try:
        run = db.query(AuditAgentRun).filter(AuditAgentRun.id == run_id).first()
        if not run:
            return

        if agent_type == "control_tester":
            result = _run_control_tester(db, client_id, wizard_inputs)
        elif agent_type == "readiness_report":
            result = _run_readiness_report(db, client_id, wizard_inputs)
        elif agent_type == "evidence_curator":
            result = _run_evidence_curator(db, client_id, wizard_inputs)
        elif agent_type == "interview_prep":
            result = _run_interview_prep(db, client_id, wizard_inputs)
        else:
            raise ValueError(f"Unknown agent_type: {agent_type}")

        run.status = "completed"
        run.result = result
        run.completed_at = datetime.now(timezone.utc)
        db.commit()

    except Exception as exc:
        logger.exception("audit agent run %s failed", run_id)
        try:
            run = db.query(AuditAgentRun).filter(AuditAgentRun.id == run_id).first()
            if run:
                run.status = "failed"
                run.error_message = str(exc)[:2000]
                run.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def _run_control_tester(db: Session, client_id: str, inputs: Dict) -> Dict:
    framework = inputs.get("framework", "")
    domains: List[str] = inputs.get("domains", [])
    depth = inputs.get("depth", "Standard (all controls)")
    purpose = inputs.get("assessment_purpose", "Internal Audit")
    scan_id: str = inputs.get("scan_id", "")

    q = db.query(FrameworkControl).filter(FrameworkControl.framework == framework)
    if domains:
        q = q.filter(FrameworkControl.domain.in_(domains))
    controls = q.order_by(FrameworkControl.domain, FrameworkControl.control_id).all()

    if not controls:
        return {"controls": [], "summary": {"total": 0, "pass": 0, "partial": 0, "fail": 0, "no_data": 0,
                                             "framework": framework, "domains_tested": domains, "depth": depth}}

    evidence_map = _build_evidence_map(db, client_id, framework, scan_id)
    raw_ctx = _load_raw_context(db, scan_id)
    llm = get_llm()

    all_results: List[Dict] = []
    batch_size = 15
    for i in range(0, len(controls), batch_size):
        batch = controls[i:i + batch_size]
        controls_text = "\n".join(
            f"- {c.control_id} | {c.domain or 'General'} | {c.title}\n"
            f"  Description: {(c.description or '')[:200]}\n"
            f"  Evidence: {evidence_map.get(c.control_id, ['No direct evidence found'])}"
            for c in batch
        )
        prompt = (
            f"You are a security control testing expert. Assess each control based on the evidence provided.\n\n"
            f"Framework: {framework}\nAssessment purpose: {purpose}\nDepth: {depth}\n\n"
            f"For each control determine:\n"
            f"- verdict: \"pass\" | \"partial\" | \"fail\" | \"no_data\"\n"
            f"- confidence: \"high\" | \"medium\" | \"low\"\n"
            f"- evidence_summary: 1 sentence on what evidence exists\n"
            f"- gaps: list of specific gaps (empty list if pass)\n"
            f"- recommendation: 1 actionable sentence\n\n"
            f"Controls and Evidence:\n{controls_text}\n"
        )
        if raw_ctx:
            prompt += f"\nRaw connector data from selected scan:\n{raw_ctx}\n"
        prompt += (
            f"\nRespond ONLY with a JSON array:\n"
            f'[{{"control_id":"...","verdict":"...","confidence":"...","evidence_summary":"...","gaps":[...],"recommendation":"..."}}]'
        )
        try:
            raw = llm.invoke(prompt)
            text = raw.content if hasattr(raw, "content") else str(raw)
            parsed = _parse_llm_json(text)
            if isinstance(parsed, list):
                all_results.extend(parsed)
        except Exception as exc:
            logger.warning("control_tester batch %d failed: %s", i, exc)
            for c in batch:
                all_results.append({"control_id": c.control_id, "verdict": "no_data",
                                     "confidence": "low", "evidence_summary": "LLM error",
                                     "gaps": [], "recommendation": ""})

    summary = {"total": len(all_results), "pass": 0, "partial": 0, "fail": 0, "no_data": 0,
               "framework": framework, "domains_tested": domains or ["All"], "depth": depth}
    ctrl_map = {c.control_id: c for c in controls}
    for r in all_results:
        v = r.get("verdict", "no_data")
        summary[v] = summary.get(v, 0) + 1
        ctrl = ctrl_map.get(r.get("control_id", ""))
        if ctrl:
            r["domain"] = ctrl.domain or "General"
            r["title"] = ctrl.title

    return {"controls": all_results, "summary": summary}


def _run_readiness_report(db: Session, client_id: str, inputs: Dict) -> Dict:
    framework = inputs.get("framework", "")
    domains: List[str] = inputs.get("domains", [])
    timeline = inputs.get("timeline", "3–6 months")
    focus = inputs.get("focus", "All gaps with fixes")
    scan_id: str = inputs.get("scan_id", "")

    q = db.query(FrameworkControl).filter(FrameworkControl.framework == framework)
    if domains:
        q = q.filter(FrameworkControl.domain.in_(domains))
    controls = q.all()

    evidence_map = _build_evidence_map(db, client_id, framework, scan_id)
    raw_ctx = _load_raw_context(db, scan_id)

    open_findings_q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open")
        .order_by(Finding.severity)
    )
    if scan_id:
        open_findings_q = open_findings_q.filter(Finding.scan_id == scan_id)
    open_findings = open_findings_q.limit(20).all()

    domain_data: Dict[str, Dict] = {}
    for c in controls:
        d = c.domain or "General"
        if d not in domain_data:
            domain_data[d] = {"total": 0, "with_evidence": 0, "control_ids": []}
        domain_data[d]["total"] += 1
        domain_data[d]["control_ids"].append(c.control_id)
        if c.control_id in evidence_map:
            domain_data[d]["with_evidence"] += 1

    sample_gaps = [f.title for f in open_findings[:5]]
    domain_lines = "\n".join(
        f"- {d}: {v['total']} controls, {v['with_evidence']} with evidence"
        for d, v in domain_data.items()
    )
    prompt = (
        f"You are an audit readiness expert. Generate a readiness report.\n\n"
        f"Framework: {framework}\nTimeline: {timeline}\nFocus: {focus}\n"
        f"Domains in scope: {', '.join(domains) or 'All'}\n\n"
        f"Domain data:\n{domain_lines}\n\n"
        f"Sample open findings: {sample_gaps}\n"
    )
    if raw_ctx:
        prompt += f"\nRaw connector data from selected scan:\n{raw_ctx}\n"
    prompt += (
        "\nReturn JSON:\n"
        '{"overall_score":0-100,"overall_assessment":"...","timeline_risk":"low|medium|high",'
        '"domains":[{"domain":"...","score":0-100,"status":"on-track|at-risk|critical",'
        '"passing":N,"failing":N,"gaps":["..."],"quick_wins":["..."]}],'
        '"critical_blockers":["..."],"quick_wins":["..."],"recommended_focus_order":["..."]}'
    )
    try:
        llm = get_llm()
        raw = llm.invoke(prompt)
        text = raw.content if hasattr(raw, "content") else str(raw)
        result = _parse_llm_json(text)
    except Exception as exc:
        result = {"error": str(exc)}

    result["framework"] = framework
    result["timeline"] = timeline
    result["focus"] = focus
    return result


def _run_evidence_curator(db: Session, client_id: str, inputs: Dict) -> Dict:
    audit_type = inputs.get("audit_type", "Annual Compliance Review")
    framework = inputs.get("framework", "")
    date_range = inputs.get("date_range", "Last 90 days")
    severities: List[str] = inputs.get("severities", ["critical", "high"])
    scan_id: str = inputs.get("scan_id", "")

    cutoff = datetime.now(timezone.utc) - timedelta(days=_date_range_days(date_range))
    sevs_lower = [s.lower() for s in severities]

    findings_q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.severity.in_(sevs_lower),
            Finding.status.in_(["open", "remediated", "accepted"]),
        )
    )
    if scan_id:
        findings_q = findings_q.filter(Finding.scan_id == scan_id)
    try:
        findings_q = findings_q.filter(Finding.created_at >= cutoff)
    except Exception:
        pass
    findings = findings_q.all()
    raw_ctx = _load_raw_context(db, scan_id)

    deficiency_count = db.query(ControlDeficiency).filter(
        ControlDeficiency.client_id == client_id,
        ControlDeficiency.status == "open",
    ).count()
    remediation_count = db.query(RemediationAction).filter(
        RemediationAction.client_id == client_id,
    ).count()
    risk_count = db.query(Risk).filter(Risk.client_id == client_id).count()

    total = len(findings)
    remediated = sum(1 for f in findings if f.status == "remediated")
    by_sev: Dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    domain_map: Dict[str, List[str]] = {}
    for f in findings:
        dom = (f.control_id or "").split("-")[0] if f.control_id else "General"
        domain_map.setdefault(dom, []).append(f"{f.title} [{f.severity}] ({f.status})")

    domain_lines = "\n".join(f"- {d}: {vs[:3]}" for d, vs in list(domain_map.items())[:15])
    prompt = (
        f"You are an audit evidence expert. Organise the following evidence for a {audit_type} audit against {framework}.\n\n"
        f"Evidence inventory:\n"
        f"- Total findings: {total} ({by_sev.get('critical',0)} critical, {by_sev.get('high',0)} high, {by_sev.get('medium',0)} medium)\n"
        f"- Remediated findings: {remediated}\n"
        f"- Open control deficiencies: {deficiency_count}\n"
        f"- Active remediation actions: {remediation_count}\n"
        f"- Open risks: {risk_count}\n\n"
        f"Findings by domain/control:\n{domain_lines}\n"
    )
    if raw_ctx:
        prompt += f"\nRaw connector data from selected scan:\n{raw_ctx}\n"
    prompt += (
        "\nReturn JSON:\n"
        '{"executive_summary":"...","coverage_score":0-100,"domains":['
        '{"domain":"...","coverage_pct":0-100,"finding_count":N,"remediated_count":N,"open_count":N,'
        '"evidence_strength":"strong|adequate|weak|missing","key_evidence":["..."],"gaps":["..."]}],'
        '"strengths":["..."],"evidence_gaps":["..."],"recommended_actions":["..."]}'
    )
    try:
        llm = get_llm()
        raw = llm.invoke(prompt)
        text = raw.content if hasattr(raw, "content") else str(raw)
        result = _parse_llm_json(text)
    except Exception as exc:
        result = {"error": str(exc)}

    result["framework"] = framework
    result["audit_type"] = audit_type
    result["date_range"] = date_range
    result["finding_totals"] = {"total": total, "remediated": remediated, "by_severity": by_sev}
    return result


def _run_interview_prep(db: Session, client_id: str, inputs: Dict) -> Dict:
    domain_topic = inputs.get("domain_topic", "")
    framework = inputs.get("framework", "")
    question_type = inputs.get("question_type", "")
    focus_aspect = inputs.get("focus_aspect", "")
    scan_id: str = inputs.get("scan_id", "")

    keywords = _DOMAIN_TOPIC_KEYWORDS.get(domain_topic, [])
    findings_q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open")
        .order_by(Finding.severity)
    )
    if scan_id:
        findings_q = findings_q.filter(Finding.scan_id == scan_id)
    all_findings = findings_q.limit(100).all()
    raw_ctx = _load_raw_context(db, scan_id)
    relevant = [
        f for f in all_findings
        if any(kw in (f.title or "").lower() for kw in keywords)
    ][:10] or all_findings[:5]

    deficiencies = (
        db.query(ControlDeficiency)
        .filter(ControlDeficiency.client_id == client_id, ControlDeficiency.framework == framework)
        .limit(10)
        .all()
    )

    findings_text = "\n".join(
        f"- {f.title} [{f.severity}] on {f.resource_id or 'unknown resource'}"
        for f in relevant
    ) or "No directly relevant open findings."
    deficiency_text = "\n".join(
        f"- {d.control_id}: {d.title}" for d in deficiencies
    ) or "No control deficiencies recorded."

    prompt = (
        f"You are an expert helping a security team prepare for an audit interview.\n\n"
        f"Audit framework: {framework}\nDomain: {domain_topic}\n"
        f"Question type: {question_type}\n"
        f"Specific focus: {focus_aspect or 'General'}\n\n"
        f"Relevant open findings ({len(relevant)} total):\n{findings_text}\n\n"
        f"Relevant control deficiencies:\n{deficiency_text}\n\n"
    )
    if raw_ctx:
        prompt += f"Raw connector data from selected scan:\n{raw_ctx}\n\n"
    prompt += (
        f"Return JSON:\n"
        '{"situation_briefing":"...","suggested_response":"...","key_evidence_to_cite":['
        '{"item":"...","where":"...","strength":"strong|adequate|weak"}],'
        '"likely_follow_up_questions":["..."],"watch_outs":["..."],"preparation_checklist":["..."]}'
    )
    try:
        llm = get_llm()
        raw = llm.invoke(prompt)
        text = raw.content if hasattr(raw, "content") else str(raw)
        result = _parse_llm_json(text)
    except Exception as exc:
        result = {"error": str(exc)}

    result["framework"] = framework
    result["domain_topic"] = domain_topic
    result["question_type"] = question_type
    return result


# ── Request/Response schemas ───────────────────────────────────────────────────

class RunRequest(BaseModel):
    agent_type: str
    wizard_inputs: Dict[str, Any]


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/clients/{client_id}/audit-agents/connectors")
async def list_audit_connectors(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return all connectors for the client that have at least one completed scan."""
    from ..models.models import Connector, ScanStatus
    connectors = (
        db.query(Connector)
        .join(Scan, Scan.connector_id == Connector.id)
        .filter(
            Connector.client_id == client_id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .distinct()
        .all()
    )
    return {
        "connectors": [
            {"id": c.id, "name": c.name, "connector_type": str(c.connector_type)}
            for c in connectors
        ]
    }


@router.get("/clients/{client_id}/audit-agents/scans")
async def list_scans_for_connector(
    client_id: str,
    connector_id: str = "",
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return completed scans for a given connector."""
    from ..models.models import ScanStatus
    q = (
        db.query(Scan)
        .filter(
            Scan.client_id == client_id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .order_by(Scan.created_at.desc())
    )
    if connector_id:
        q = q.filter(Scan.connector_id == connector_id)
    scans = q.limit(50).all()
    return {
        "scans": [
            {
                "id": s.id,
                "name": s.name or s.scan_type,
                "scan_type": str(s.scan_type) if s.scan_type else "",
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "total": (s.summary or {}).get("total", 0),
                "has_raw_context": bool(s.raw_context),
            }
            for s in scans
        ]
    }


@router.get("/clients/{client_id}/audit-agents/framework-domains")
async def get_framework_domains(
    client_id: str,
    framework: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    rows = (
        db.query(distinct(FrameworkControl.domain))
        .filter(FrameworkControl.framework == framework, FrameworkControl.domain.isnot(None))
        .order_by(FrameworkControl.domain)
        .all()
    )
    return {"domains": [r[0] for r in rows if r[0]]}


@router.post("/clients/{client_id}/audit-agents/run")
async def start_audit_agent_run(
    client_id: str,
    body: RunRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    valid_types = {"control_tester", "readiness_report", "evidence_curator", "interview_prep"}
    if body.agent_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Unknown agent_type: {body.agent_type}")

    run = AuditAgentRun(
        client_id=client_id,
        agent_type=body.agent_type,
        wizard_inputs=body.wizard_inputs,
        status="running",
        created_by=user.get("preferred_username") or user.get("email") or user.get("sub", ""),
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    background_tasks.add_task(
        _run_agent, run.id, settings.DATABASE_URL, client_id, body.agent_type, body.wizard_inputs
    )
    return {"run_id": run.id}


@router.get("/clients/{client_id}/audit-agents/runs")
async def list_audit_agent_runs(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    runs = (
        db.query(AuditAgentRun)
        .filter(AuditAgentRun.client_id == client_id)
        .order_by(AuditAgentRun.created_at.desc())
        .limit(20)
        .all()
    )
    return [
        {
            "id": r.id,
            "agent_type": r.agent_type,
            "status": r.status,
            "wizard_inputs": r.wizard_inputs,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        }
        for r in runs
    ]


@router.get("/clients/{client_id}/audit-agents/runs/{run_id}")
async def get_audit_agent_run(
    client_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    run = db.query(AuditAgentRun).filter(
        AuditAgentRun.id == run_id,
        AuditAgentRun.client_id == client_id,
    ).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {
        "id": run.id,
        "agent_type": run.agent_type,
        "status": run.status,
        "wizard_inputs": run.wizard_inputs,
        "result": run.result,
        "error_message": run.error_message,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }
