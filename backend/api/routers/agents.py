"""AI Agent execution endpoints."""
import asyncio
import json as _json
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
from api.models.models import (
    AgentRun, AgentFeedback, AgentType, Scan, Finding, Risk, RiskLevel,
    ThreatEntry, ControlDeficiency, RemediationAction,
    CustomFramework, CustomFrameworkControl,
    FrameworkAssessment, FrameworkType, RiskProposal,
)
from api.schemas.schemas import AgentRunRequest, AgentRunResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

router = APIRouter(prefix="/clients/{client_id}/agents", tags=["agents"])


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


_FW_TEXT_TO_ENUM = {
    "nist": FrameworkType.NIST_CSF,
    "nist csf": FrameworkType.NIST_CSF,
    "nist_csf": FrameworkType.NIST_CSF,
    "nist 800": FrameworkType.NIST_800_53,
    "nist_800_53": FrameworkType.NIST_800_53,
    "iso": FrameworkType.ISO_27001,
    "iso 27001": FrameworkType.ISO_27001,
    "iso_27001": FrameworkType.ISO_27001,
    "gdpr": FrameworkType.GDPR,
    "pci": FrameworkType.PCI_DSS,
    "pci dss": FrameworkType.PCI_DSS,
    "pci_dss": FrameworkType.PCI_DSS,
    "soc2": FrameworkType.SOC2,
    "soc 2": FrameworkType.SOC2,
    "cis": FrameworkType.CIS_V8,
    "cis_v8": FrameworkType.CIS_V8,
    "gcc": FrameworkType.GCC_IM8,
    "gcc_im8": FrameworkType.GCC_IM8,
    "im8": FrameworkType.GCC_IM8,
    "nist ai rmf": FrameworkType.NIST_AI_RMF,
    "nist_ai_rmf": FrameworkType.NIST_AI_RMF,
}

def _text_to_fw_enum(ref_str: str):
    """Map a free-text framework reference to a FrameworkType enum, or None."""
    s = ref_str.lower()
    # Try direct enum value first
    for ft in FrameworkType:
        if ft.value in s or s == ft.value:
            return ft
    # Keyword matching
    for key, ft in _FW_TEXT_TO_ENUM.items():
        if key in s:
            return ft
    return None


def _persist_compliance(db, client_id: str, run_id: str, scan_id, comp_result: dict, framework_slug: str = "nist_csf") -> int:
    findings_out = comp_result.get("findings") or []
    audit_score = comp_result.get("audit_readiness_score")

    # Track per-framework control results for heatmap
    fw_control_results: dict = {}  # FrameworkType → {ctrl_id: {status, severity, title}}

    for f in findings_out:
        refs = f.get("framework_references") or []
        control_id = refs[0] if refs else None
        framework_text = None
        fw_enum = None
        for ref in refs:
            ref_s = str(ref).upper()
            if "NIST" in ref_s:
                framework_text = "NIST CSF 2.0"
            elif "ISO" in ref_s:
                framework_text = "ISO 27001"
            elif "GDPR" in ref_s:
                framework_text = "GDPR"
            elif "PCI" in ref_s:
                framework_text = "PCI DSS"
            elif "HIPAA" in ref_s:
                framework_text = "HIPAA"
            if framework_text:
                fw_enum = _text_to_fw_enum(str(ref))
                break

        db.add(ControlDeficiency(
            client_id=client_id,
            agent_run_id=run_id,
            scan_id=scan_id,
            finding_id=f.get("finding_id"),
            control_id=control_id,
            framework=framework_text,
            severity=(f.get("severity") or "medium").lower(),
            title=f.get("title") or "(untitled)",
            gap_description=f.get("description"),
            regulatory_reference=", ".join(str(r) for r in refs) if refs else None,
            remediation=f.get("remediation"),
            audit_readiness_score=audit_score,
        ))

        # Accumulate for FrameworkAssessment
        if fw_enum and control_id:
            sev = (f.get("severity") or "medium").lower()
            fw_control_results.setdefault(fw_enum, {})[control_id] = {
                "status": "failed",
                "severity": sev,
                "title": f.get("title") or "(untitled)",
            }

    # Ensure the selected framework is always represented in the heatmap,
    # even if the LLM didn't emit explicit framework_references.
    for fw_src in [framework_slug, comp_result.get("framework"), comp_result.get("framework_key")]:
        if not fw_src:
            continue
        extra_enum = _text_to_fw_enum(str(fw_src))
        if extra_enum and extra_enum not in fw_control_results:
            fw_control_results[extra_enum] = {}

    # Upsert FrameworkAssessment rows so the heatmap has data
    from datetime import datetime, timezone as tz
    now = datetime.now(tz.utc)
    for fw_enum, ctrl_map in fw_control_results.items():
        passed = sum(1 for v in ctrl_map.values() if v.get("status") == "passed")
        failed = sum(1 for v in ctrl_map.values() if v.get("status") == "failed")
        total = len(ctrl_map)
        score = round((passed / total * 100) if total > 0 else 0.0, 1)

        existing = (
            db.query(FrameworkAssessment)
            .filter(
                FrameworkAssessment.client_id == client_id,
                FrameworkAssessment.framework == fw_enum,
            )
            .order_by(FrameworkAssessment.assessed_at.desc())
            .first()
        )
        if existing:
            # Merge new failures into existing control_results
            merged = dict(existing.control_results or {})
            merged.update(ctrl_map)
            existing.control_results = merged
            existing.controls_total = len(merged)
            existing.controls_failed = sum(1 for v in merged.values() if v.get("status") == "failed")
            existing.controls_passed = len(merged) - existing.controls_failed
            existing.overall_score = round(
                (existing.controls_passed / existing.controls_total * 100)
                if existing.controls_total > 0 else 0.0, 1
            )
            existing.assessed_at = now
            if scan_id:
                existing.scan_id = scan_id
        else:
            db.add(FrameworkAssessment(
                client_id=client_id,
                framework=fw_enum,
                scan_id=scan_id,
                overall_score=score,
                controls_total=total,
                controls_passed=passed,
                controls_failed=failed,
                controls_partial=0,
                control_results=ctrl_map,
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


def _persist_to_registers(db, agent_val: str, client_id: str, run_id: str, scan_id, result: dict, raw_findings: list, framework_slug: str = "nist_csf"):
    """Route each agent type's output to the correct dedicated register.

    Source → Register mapping:
      risk_manager   → RiskProposal table (source=ai, status=pending)
      orchestrator   → RiskProposal table + ThreatEntry + ControlDeficiency + RemediationAction
      threat_intel   → ThreatEntry table
      compliance_monitor → ControlDeficiency table + FrameworkAssessment (heatmap)
      remediation    → RemediationAction table
      va_scanner / framework_analyst → no register (output_data only)
    """
    if agent_val == "orchestrator":
        # Route findings-derived risks through the staging gate (not directly to register)
        if raw_findings:
            from agents.risk.risk_agent import map_to_risk_register_structured
            structured = map_to_risk_register_structured(raw_findings)
            for r in structured:
                notes = (
                    f"AI pre-assessment — risk_level: {r['risk_level']}, "
                    f"likelihood: {r['likelihood']}/5, impact: {r['impact']}/5, "
                    f"score: {r['risk_score']}. Treatment: {r.get('treatment', '')}"
                )
                db.add(RiskProposal(
                    client_id=client_id,
                    title=r["title"],
                    description=r.get("description") or None,
                    category=r.get("category"),
                    risk_type="Security",
                    source="ai",
                    source_agent_run_id=run_id,
                    status="pending",
                    notes=notes,
                ))
            result["risks_created"] = len(structured)
        # Sub-agent register rows
        result["threats_created"] = _persist_threat_intel(db, client_id, run_id, scan_id, result.get("threat_intel") or {})
        result["deficiencies_created"] = _persist_compliance(db, client_id, run_id, scan_id, result.get("framework_analysis") or {}, framework_slug=framework_slug)
        result["actions_created"] = _persist_remediation(db, client_id, run_id, scan_id, result.get("remediation") or {})

    elif agent_val == "risk_manager" and raw_findings:
        from agents.risk.risk_agent import map_to_risk_register_structured
        structured = map_to_risk_register_structured(raw_findings)
        for r in structured:
            notes = (
                f"AI pre-assessment — risk_level: {r['risk_level']}, "
                f"likelihood: {r['likelihood']}/5, impact: {r['impact']}/5, "
                f"score: {r['risk_score']}. Treatment: {r.get('treatment', '')}"
            )
            db.add(RiskProposal(
                client_id=client_id,
                title=r["title"],
                description=r.get("description") or None,
                category=r.get("category"),
                risk_type="Security",
                source="ai",
                source_agent_run_id=run_id,
                status="pending",
                notes=notes,
            ))
        result["risks_created"] = len(structured)

    elif agent_val == "threat_intel":
        result["threats_created"] = _persist_threat_intel(db, client_id, run_id, scan_id, result)

    elif agent_val == "compliance_monitor":
        result["deficiencies_created"] = _persist_compliance(db, client_id, run_id, scan_id, result, framework_slug=framework_slug)

    elif agent_val == "remediation":
        result["actions_created"] = _persist_remediation(db, client_id, run_id, scan_id, result)


async def _run_config_review_task(run_id: str, client_id: str) -> None:
    """Background task: pull asset configs from a selected platform and run LLM security review."""
    import json
    from db.database import SessionLocal
    from api.models.models import Asset, Finding, Severity, Scan, ScanType, ScanStatus, Connector
    from core.ai_providers import get_llm
    db = SessionLocal()
    try:
        run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
        if run is None:
            return
        run.status = "running"
        db.commit()

        # Determine connector_type from linked scan (user picked a platform connector)
        source_scan_id = run.scan_id
        connector_type_filter = None
        connector_label = "All platforms"
        if source_scan_id:
            source_scan = db.query(Scan).filter(Scan.id == source_scan_id).first()
            if source_scan and source_scan.connector:
                ct = source_scan.connector.connector_type
                connector_type_filter = ct.value if hasattr(ct, "value") else str(ct)
                connector_label = connector_type_filter.upper()

        # Always create a new scan record for the config review findings
        scan_name = f"AI Configuration Review — {connector_label}"
        new_scan = Scan(
            client_id=client_id,
            name=scan_name,
            scan_type=ScanType.CONFIGURATION,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)
        run.scan_id = new_scan.id
        db.commit()
        review_scan_id = new_scan.id

        # Query assets — filter by connector_type if one was selected
        asset_query = db.query(Asset).filter(Asset.client_id == client_id)
        if connector_type_filter:
            # Join via connector: Asset.connector_id → Connector.connector_type
            asset_query = (
                asset_query
                .join(Connector, Asset.connector_id == Connector.id)
                .filter(Connector.connector_type == connector_type_filter)
            )
        assets = asset_query.limit(30).all()

        run.progress_message = f"Reviewing {len(assets)} asset configurations..."
        db.commit()

        if not assets:
            run.status = "failed"
            no_assets_msg = (
                f"No assets found for connector '{connector_type_filter}'. "
                "Ensure the connector has synced assets (run a platform scan first)."
                if connector_type_filter else
                "No assets found. Connect a cloud platform and run an asset sync first."
            )
            run.error_message = no_assets_msg
            run.completed_at = datetime.now(timezone.utc)
            s = db.query(Scan).filter(Scan.id == review_scan_id).first()
            if s and s.status == ScanStatus.RUNNING:
                s.status = ScanStatus.FAILED
                s.error_message = "No assets"
            db.commit()
            return

        lines = []
        for a in assets:
            meta = a.provider_metadata or {}
            meta_str = json.dumps(meta)[:1500] if meta else "(no config)"
            lines.append(f"Asset: {a.name}\nType: {a.asset_type or a.asset_class}\nID: {a.external_id}\nConfig:\n{meta_str}\n---")
        config_context = "\n".join(lines)

        prompt = f"""You are a cloud security configuration auditor. Review these asset configurations and identify security misconfigurations.

Assets:
{config_context}

Return ONLY valid JSON (no markdown):
{{
  "findings": [
    {{
      "title": "...",
      "description": "...",
      "severity": "critical|high|medium|low|info",
      "resource_id": "asset external_id",
      "resource_type": "asset type",
      "remediation": "...",
      "control_id": "optional control like CIS 1.1"
    }}
  ],
  "summary": "2-3 sentence overall assessment"
}}

Focus on: overly permissive IAM, unencrypted storage, missing logging, public exposure, weak authentication config.
Return empty findings array if config looks secure. Max 20 findings."""

        run.progress_message = "Running AI security configuration review..."
        db.commit()

        llm = get_llm()
        response = llm.invoke(prompt)
        raw = response.content if hasattr(response, "content") else str(response)
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        parsed = json.loads(raw)

        created = 0
        sev_counts: dict = {}
        for f in parsed.get("findings", []):
            sev_raw = (f.get("severity") or "medium").lower()
            try:
                sev = Severity(sev_raw)
            except ValueError:
                sev = Severity.MEDIUM
            db.add(Finding(
                scan_id=review_scan_id,
                title=f.get("title", "Misconfiguration"),
                description=f.get("description"),
                severity=sev,
                resource_id=f.get("resource_id"),
                resource_type=f.get("resource_type"),
                remediation=f.get("remediation"),
                control_id=f.get("control_id"),
                status="open",
            ))
            sev_counts[sev_raw] = sev_counts.get(sev_raw, 0) + 1
            created += 1

        # Mark the config review scan completed
        s = db.query(Scan).filter(Scan.id == review_scan_id).first()
        if s:
            s.status = ScanStatus.COMPLETED
            s.completed_at = datetime.now(timezone.utc)
            s.summary = {"total": created, **sev_counts}

        run.status = "completed"
        run.output_data = {"summary": parsed.get("summary", ""), "findings_created": created}
        run.completed_at = datetime.now(timezone.utc)
        db.commit()

    except Exception as exc:
        try:
            run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
            if run:
                run.status = "failed"
                run.error_message = str(exc)
                run.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def _set_progress(db, run, msg: str) -> None:
    """Update progress_message on an AgentRun and commit so SSE stream picks it up."""
    run.progress_message = msg
    db.commit()


async def _run_agent_task(
    run_id: str,
    client_id: str,
    agent_type_val: str,
    findings: list,
    client_name: str,
    framework_slug: str,
    custom_context,
    raw_context_str,
):
    """Background task: runs the agent in a fresh DB session so the HTTP thread is not blocked."""
    if agent_type_val == "configuration_review":
        await _run_config_review_task(run_id, client_id)
        return

    from db.database import SessionLocal
    db = SessionLocal()
    try:
        run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
        if run is None:
            return
        run.status = "running"
        db.commit()

        # ── Cross-session learning: inject prior corrections for this client+agent ──
        from api.models.models import AgentFeedback as _AgentFeedback
        prior_corrections = (
            db.query(_AgentFeedback)
            .filter(
                _AgentFeedback.client_id == client_id,
                _AgentFeedback.agent_type == agent_type_val,
                _AgentFeedback.feedback_type == "correction",
                _AgentFeedback.correction_text.isnot(None),
            )
            .order_by(_AgentFeedback.created_at.desc())
            .limit(5)
            .all()
        )
        if prior_corrections:
            corrections_text = "\n".join(
                f"- {c.correction_text}" for c in prior_corrections if c.correction_text
            )
            prior_context = (
                "## Prior User Corrections for This Client\n"
                "The user has previously corrected this agent's output for this client. "
                "Apply these corrections in your current analysis:\n\n"
                f"{corrections_text}"
            )
            existing = custom_context or ""
            custom_context = (prior_context + "\n\n" + existing).strip() if existing else prior_context

        _set_progress(db, run, f"Loading {len(findings)} findings and building analysis context...")

        from agents.orchestrator.orchestrator import AgentOrchestrator
        orchestrator = AgentOrchestrator()

        if custom_context:
            orchestrator.framework.extra_context = custom_context
            orchestrator.compliance.extra_context = custom_context

        orchestrator.set_resource_inventory(raw_context_str)

        _set_progress(db, run, f"Running {agent_type_val.replace('_', ' ')} analysis...")

        result = await orchestrator.run_single_agent(
            agent_type_val,
            findings,
            client_name,
            framework=framework_slug,
        )

        run.status = "completed"
        run.output_data = result
        run.completed_at = datetime.now(timezone.utc)
        _persist_to_registers(db, agent_type_val, client_id, run_id, run.scan_id, result, findings, framework_slug=framework_slug)
        db.commit()

    except Exception as exc:
        try:
            run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
            if run:
                run.status = "failed"
                run.error_message = str(exc)
                run.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


@router.post("/run/", response_model=AgentRunResponse, dependencies=[Depends(require_editor_anywhere)])
async def run_agent(
    client_id: str,
    payload: AgentRunRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    # Load findings if scan_id provided. Refuse if the scan returned
    # nothing — running an agent on an empty/incomplete scan wastes LLM
    # budget and produces useless output. Tell the user to re-scan first.
    findings = []
    scan = None
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
        if finding_count == 0 and payload.agent_type.value != "configuration_review":
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

    # Resolve framework: comes from input_data["framework"], default nist_csf
    input_data = payload.input_data or {}
    framework_slug: str = input_data.get("framework", "nist_csf") or "nist_csf"

    # Check if this is a custom framework slug (not a standard FrameworkType value)
    standard_values = {e.value for e in __import__("api.models.models", fromlist=["FrameworkType"]).FrameworkType}
    custom_context: Optional[str] = None
    if framework_slug not in standard_values:
        cf = db.query(CustomFramework).filter(CustomFramework.slug == framework_slug).first()
        if cf is None:
            raise HTTPException(status_code=404, detail=f"Framework '{framework_slug}' not found")
        # Build a controls context string for the agent
        controls = (
            db.query(CustomFrameworkControl)
            .filter(CustomFrameworkControl.custom_framework_id == cf.id)
            .all()
        )
        lines = [f"# Custom Framework: {cf.name}", cf.description or "", ""]
        for cc in controls:
            fc = cc.framework_control
            lines.append(
                f"- {fc.control_id}: {fc.title}"
                + (f" — {fc.description[:200]}" if fc.description else "")
            )
        custom_context = "\n".join(lines)
        # Use the human name as the framework label for the agent
        framework_slug = cf.name

    # Load raw resource inventory from the scan if available
    raw_context_str: Optional[str] = None
    if scan is not None:
        raw_ctx = getattr(scan, "raw_context", None)
        if raw_ctx:
            raw_context_str = raw_ctx

    agent_run_db = AgentRun(
        client_id=client_id,
        agent_type=payload.agent_type,
        scan_id=payload.scan_id,
        status="queued",
        input_data=input_data,
    )
    db.add(agent_run_db)
    db.commit()
    db.refresh(agent_run_db)

    background_tasks.add_task(
        _run_agent_task,
        run_id=agent_run_db.id,
        client_id=client_id,
        agent_type_val=payload.agent_type.value,
        findings=findings,
        client_name=client_name,
        framework_slug=framework_slug,
        custom_context=custom_context,
        raw_context_str=raw_context_str,
    )

    return agent_run_db


@router.get("/runs/filter/")
async def filter_agent_runs(
    client_id: str,
    agent_type: Optional[str] = None,
    scan_id: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Filter agent runs by type and/or scan. Used by contextual report panels."""
    q = db.query(AgentRun).filter(
        AgentRun.client_id == client_id,
        AgentRun.hidden_at.is_(None),
        AgentRun.status == "completed",
    )
    if agent_type:
        types = [t.strip() for t in agent_type.split(",")]
        q = q.filter(AgentRun.agent_type.in_(types))
    if scan_id:
        q = q.filter(AgentRun.scan_id == scan_id)
    return q.order_by(AgentRun.started_at.desc()).limit(limit).all()


@router.get("/runs/", response_model=List[AgentRunResponse])
async def list_agent_runs(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return (
        db.query(AgentRun)
        .filter(AgentRun.client_id == client_id, AgentRun.hidden_at.is_(None))
        .order_by(AgentRun.started_at.desc())
        .limit(200)
        .all()
    )


@router.get("/runs/hidden/", response_model=List[AgentRunResponse])
async def list_hidden_agent_runs(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Runs soft-deleted by the user — shown in the trash page."""
    return (
        db.query(AgentRun)
        .filter(AgentRun.client_id == client_id, AgentRun.hidden_at.isnot(None))
        .order_by(AgentRun.hidden_at.desc())
        .limit(200)
        .all()
    )


@router.get("/runs/{run_id}", response_model=AgentRunResponse)
async def get_agent_run(client_id: str, run_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.client_id == client_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Agent run not found")
    return run


@router.get("/runs/{run_id}/stream")
async def stream_agent_run(
    client_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """SSE endpoint: streams agent run progress messages until completion.

    Clients should connect with EventSource immediately after POSTing to /run/.
    Events: {status, message} until done=true with full output_data payload.
    """
    async def generate():
        last_msg = ""
        for _ in range(300):  # max 5 minutes at 1s polling
            run = db.query(AgentRun).filter(
                AgentRun.id == run_id, AgentRun.client_id == client_id
            ).first()
            if not run:
                yield f"data: {_json.dumps({'error': 'not_found'})}\n\n"
                return

            msg = getattr(run, "progress_message", None) or run.status
            status = run.status

            if msg != last_msg:
                last_msg = msg
                yield f"data: {_json.dumps({'status': status, 'message': msg})}\n\n"

            if status in ("completed", "failed"):
                payload = {
                    "status": status,
                    "done": True,
                    "run_id": run_id,
                    "output_data": run.output_data,
                    "error_message": run.error_message,
                }
                yield f"data: {_json.dumps(payload)}\n\n"
                return

            await asyncio.sleep(1)
        yield f"data: {_json.dumps({'status': 'timeout', 'done': True})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/runs/{run_id}/feedback", dependencies=[Depends(get_current_user)])
async def submit_agent_feedback(
    client_id: str,
    run_id: str,
    payload: dict,
    db: Session = Depends(get_db),
):
    """Submit thumbs-up or correction feedback on a completed agent run.

    payload: {"feedback_type": "positive"|"correction", "correction_text": "..."}
    Corrections are injected into subsequent runs of the same agent type for this client.
    """
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.client_id == client_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    feedback = AgentFeedback(
        client_id=client_id,
        agent_type=run.agent_type.value if hasattr(run.agent_type, "value") else str(run.agent_type),
        run_id=run_id,
        feedback_type=payload.get("feedback_type", "correction"),
        correction_text=payload.get("correction_text"),
    )
    db.add(feedback)
    db.commit()
    return {"saved": True}


@router.get("/feedback/")
async def list_agent_feedback(
    client_id: str,
    agent_type: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List feedback submitted for this client's agent runs."""
    q = db.query(AgentFeedback).filter(AgentFeedback.client_id == client_id)
    if agent_type:
        q = q.filter(AgentFeedback.agent_type == agent_type)
    return q.order_by(AgentFeedback.created_at.desc()).limit(50).all()


@router.delete("/runs/{run_id}")
async def delete_agent_run(client_id: str, run_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Soft-delete: set hidden_at. Run moves to trash; use /permanent to hard-delete."""
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.client_id == client_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Agent run not found")
    run.hidden_at = datetime.now(timezone.utc)
    db.commit()
    return {"archived": True}


@router.post("/runs/{run_id}/restore")
async def restore_agent_run(client_id: str, run_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Restore a soft-deleted run back to the active list."""
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.client_id == client_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Agent run not found")
    run.hidden_at = None
    db.commit()
    return {"restored": True}


@router.delete("/runs/{run_id}/permanent")
async def permanent_delete_agent_run(client_id: str, run_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Hard-delete. Clears FK references in register tables first."""
    from api.models.models import ThreatEntry, ControlDeficiency, RemediationAction, ScanBlackboardEntry
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.client_id == client_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Agent run not found")
    for model in (ThreatEntry, ControlDeficiency, RemediationAction, ScanBlackboardEntry):
        db.query(model).filter(model.agent_run_id == run_id).update(
            {"agent_run_id": None}, synchronize_session=False
        )
    db.delete(run)
    db.commit()
    return {"deleted": True}
