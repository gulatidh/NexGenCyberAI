"""AI Agent execution endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone
from api.models.models import (
    AgentRun, AgentType, Scan, Finding, Risk, RiskLevel,
    ThreatEntry, ControlDeficiency, RemediationAction,
)
from api.schemas.schemas import AgentRunRequest, AgentRunResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

router = APIRouter(prefix="/clients/{client_id}/agents", tags=["agents"])
_orchestrator = None


def _persist_threat_intel(db, client_id: str, run_id: str, scan_id, threat_result: dict) -> int:
    technique_map = threat_result.get("technique_mapping") or {}
    findings_out = threat_result.get("findings") or []
    for f in findings_out:
        fid = f.get("finding_id", "")
        refs = f.get("framework_references") or []
        technique_id, technique_name, tactic, confidence = None, None, None, None
        for ref in refs:
            if "T" in str(ref):
                tid = str(ref).split()[-1] if " " in str(ref) else str(ref)
                if tid in technique_map:
                    tm = technique_map[tid]
                    technique_id = tid
                    technique_name = tm.get("name")
                    tactic = tm.get("tactic")
                    confidence = tm.get("confidence")
                break
        db.add(ThreatEntry(
            client_id=client_id,
            agent_run_id=run_id,
            scan_id=scan_id,
            finding_id=fid,
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence=confidence,
            severity=(f.get("severity") or "medium").lower(),
            title=f.get("title") or "(untitled)",
            description=f.get("description"),
            remediation=f.get("remediation"),
            framework_references=refs,
        ))
    return len(findings_out)


def _persist_compliance(db, client_id: str, run_id: str, scan_id, comp_result: dict) -> int:
    findings_out = comp_result.get("findings") or []
    audit_score = comp_result.get("audit_readiness_score")
    for f in findings_out:
        refs = f.get("framework_references") or []
        control_id = refs[0] if refs else None
        framework = None
        for ref in refs:
            ref_s = str(ref).upper()
            if "NIST" in ref_s:
                framework = "NIST CSF 2.0"
            elif "ISO" in ref_s:
                framework = "ISO 27001"
            elif "GDPR" in ref_s:
                framework = "GDPR"
            elif "PCI" in ref_s:
                framework = "PCI DSS"
            elif "HIPAA" in ref_s:
                framework = "HIPAA"
            if framework:
                break
        db.add(ControlDeficiency(
            client_id=client_id,
            agent_run_id=run_id,
            scan_id=scan_id,
            finding_id=f.get("finding_id"),
            control_id=control_id,
            framework=framework,
            severity=(f.get("severity") or "medium").lower(),
            title=f.get("title") or "(untitled)",
            gap_description=f.get("description"),
            regulatory_reference=", ".join(str(r) for r in refs) if refs else None,
            remediation=f.get("remediation"),
            audit_readiness_score=audit_score,
        ))
    return len(findings_out)


def _persist_remediation(db, client_id: str, run_id: str, scan_id, rem_result: dict) -> int:
    recs = rem_result.get("recommendations") or []
    for rec in recs:
        action_text = rec.get("action") or ""
        db.add(RemediationAction(
            client_id=client_id,
            agent_run_id=run_id,
            scan_id=scan_id,
            title=action_text[:120] if action_text else None,
            action=action_text,
            band=rec.get("band"),
            priority=rec.get("priority") or 0,
            effort=rec.get("effort"),
            impact=rec.get("impact"),
        ))
    return len(recs)


def _persist_to_registers(db, agent_val: str, client_id: str, run_id: str, scan_id, result: dict, raw_findings: list):
    """Route each agent type's output to the correct dedicated register.

    Source → Register mapping:
      risk_manager   → Risk table
      orchestrator   → Risk table + ThreatEntry + ControlDeficiency + RemediationAction
      threat_intel   → ThreatEntry table
      compliance_monitor → ControlDeficiency table
      remediation    → RemediationAction table
      va_scanner / framework_analyst → no register (output_data only)
    """
    if agent_val == "orchestrator":
        # Risk rows from raw scan findings
        if raw_findings:
            from agents.risk.risk_agent import map_to_risk_register_structured
            structured = map_to_risk_register_structured(raw_findings)
            for r in structured:
                db.add(Risk(
                    client_id=client_id,
                    title=r["title"],
                    description=r.get("description") or None,
                    risk_level=RiskLevel(r["risk_level"]),
                    likelihood=r["likelihood"],
                    impact=r["impact"],
                    risk_score=r["risk_score"],
                    category=r.get("category"),
                    status="open",
                    finding_ids=[],
                ))
            result["risks_created"] = len(structured)
        # Sub-agent register rows
        result["threats_created"] = _persist_threat_intel(db, client_id, run_id, scan_id, result.get("threat_intel") or {})
        result["deficiencies_created"] = _persist_compliance(db, client_id, run_id, scan_id, result.get("framework_analysis") or {})
        result["actions_created"] = _persist_remediation(db, client_id, run_id, scan_id, result.get("remediation") or {})

    elif agent_val == "risk_manager" and raw_findings:
        from agents.risk.risk_agent import map_to_risk_register_structured
        structured = map_to_risk_register_structured(raw_findings)
        for r in structured:
            db.add(Risk(
                client_id=client_id,
                title=r["title"],
                description=r.get("description") or None,
                risk_level=RiskLevel(r["risk_level"]),
                likelihood=r["likelihood"],
                impact=r["impact"],
                risk_score=r["risk_score"],
                category=r.get("category"),
                status="open",
                finding_ids=[],
            ))
        result["risks_created"] = len(structured)

    elif agent_val == "threat_intel":
        result["threats_created"] = _persist_threat_intel(db, client_id, run_id, scan_id, result)

    elif agent_val == "compliance_monitor":
        result["deficiencies_created"] = _persist_compliance(db, client_id, run_id, scan_id, result)

    elif agent_val == "remediation":
        result["actions_created"] = _persist_remediation(db, client_id, run_id, scan_id, result)


def _get_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        from agents.orchestrator.orchestrator import AgentOrchestrator
        _orchestrator = AgentOrchestrator()
    return _orchestrator


@router.post("/run/", response_model=AgentRunResponse, dependencies=[Depends(require_editor_anywhere)])
async def run_agent(
    client_id: str,
    payload: AgentRunRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    # Load findings if scan_id provided. Refuse if the scan returned
    # nothing — running an agent on an empty/incomplete scan wastes LLM
    # budget and produces useless output. Tell the user to re-scan first.
    findings = []
    if payload.scan_id:
        from api.models.models import Scan as _Scan, ScanStatus as _ScanStatus
        scan = db.query(_Scan).filter(_Scan.id == payload.scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan_status = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
        if scan_status in ("pending", "running"):
            raise HTTPException(
                status_code=422,
                detail=f"Scan is still {scan_status}. Wait for it to complete before running an AI agent.",
            )
        finding_count = db.query(Finding).filter(Finding.scan_id == payload.scan_id).count()
        if finding_count == 0:
            raise HTTPException(
                status_code=422,
                detail=(
                    "This scan has no findings to analyse. Re-run the scan "
                    "(or pick a scan with results) before invoking an AI agent."
                ),
            )
        raw = db.query(Finding).filter(Finding.scan_id == payload.scan_id).all()
        findings = [
            {
                "title": f.title,
                "description": f.description or "",
                "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                "resource_id": f.resource_id or "",
                "control_id": f.control_id or "",
                "cve_id": f.cve_id or "",
                "cvss_score": f.cvss_score or 0,
            }
            for f in raw
        ]

    from api.models.models import Client
    client = db.query(Client).filter(Client.id == client_id).first()
    client_name = client.name if client else "Unknown"

    agent_run_db = AgentRun(
        client_id=client_id,
        agent_type=payload.agent_type,
        scan_id=payload.scan_id,
        status="running",
        input_data=payload.input_data or {},
    )
    db.add(agent_run_db)
    db.commit()
    db.refresh(agent_run_db)

    try:
        result = await _get_orchestrator().run_single_agent(
            payload.agent_type.value,
            findings,
            client_name,
        )
        agent_run_db.output_data = result
        agent_run_db.status = "completed"

        # Route each agent's structured output to the appropriate register
        agent_val = payload.agent_type.value
        _persist_to_registers(
            db, agent_val, client_id, agent_run_db.id, payload.scan_id, result, findings
        )

    except Exception as exc:
        agent_run_db.status = "failed"
        agent_run_db.error_message = str(exc)
        result = {"error": str(exc)}

    agent_run_db.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(agent_run_db)
    return agent_run_db


@router.get("/runs/", response_model=List[AgentRunResponse])
async def list_agent_runs(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(AgentRun).filter(AgentRun.client_id == client_id).order_by(AgentRun.started_at.desc()).limit(20).all()


@router.get("/runs/{run_id}", response_model=AgentRunResponse)
async def get_agent_run(client_id: str, run_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.client_id == client_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Agent run not found")
    return run


@router.delete("/runs/{run_id}")
async def delete_agent_run(client_id: str, run_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Remove a single agent run — useful for clearing out empty / failed /
    stuck-running runs from the Risk Register's AI Agent Risk Analysis tiles."""
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.client_id == client_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Agent run not found")
    db.delete(run)
    db.commit()
    return {"deleted": True}
