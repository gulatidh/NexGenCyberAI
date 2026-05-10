"""Scan management and execution endpoints."""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
import json
from api.models.models import Scan, ScanStatus, Finding, Connector, FrameworkAssessment, AgentRun, AgentType
from api.schemas.schemas import ScanCreate, ScanResponse, FindingResponse, FindingUpdate
from db.database import get_db
from core.security import get_current_user
from core.encryption import decrypt
from connectors.factory import get_connector
from connectors.sync import sync_connector_assets
from services.compliance import recompute_all_frameworks_for_client, recompute_client_framework

router = APIRouter(prefix="/clients/{client_id}/scans", tags=["scans"])
_orchestrator = None


def _get_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        from agents.orchestrator.orchestrator import AgentOrchestrator
        _orchestrator = AgentOrchestrator()
    return _orchestrator


async def _execute_scan(
    scan_id: str,
    db_url: str,
    asset_external_id: Optional[str] = None,
    control_id_filter: Optional[List[str]] = None,
):
    """Background task: run the scan and populate findings.

    Optional filters (all additive — a finding must pass every filter that's set):
      - asset_external_id: keep only findings whose resource_id matches the asset
      - control_id_filter: keep only findings whose control_mappings[scan.framework]
        or normalized control_id intersects this list (used by framework-scoped scans)
    """
    from db.database import SessionLocal
    from api.models.models import Client, ScanType
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        all_findings = []

        if scan.connector_id:
            connector_db = db.query(Connector).filter(Connector.id == scan.connector_id).first()
            if connector_db:
                # Refresh asset inventory before the scan so findings join to fresh assets.
                try:
                    await sync_connector_assets(db, connector_db)
                except Exception as exc:
                    logger_msg = f"Pre-scan asset sync failed for connector {connector_db.id}: {exc}"
                    import logging as _lg
                    _lg.getLogger(__name__).warning(logger_msg)

                creds = json.loads(decrypt(connector_db.credentials_enc))
                connector = get_connector(connector_db.connector_type, creds, connector_db.config or {})
                if scan.scan_type in ("vulnerability", "full"):
                    vuln_findings = await connector.run_vulnerability_scan()
                    all_findings.extend(vuln_findings)
                if scan.scan_type in ("configuration", "compliance", "full"):
                    config_findings = await connector.run_configuration_review()
                    all_findings.extend(config_findings)

        if asset_external_id:
            target = asset_external_id.lower()
            all_findings = [
                f for f in all_findings
                if (f.resource_id or "").lower() == target
                or target in (f.resource_id or "").lower()
            ]

        if control_id_filter:
            from services.compliance import _normalize as _norm_ctrl
            wanted = {_norm_ctrl(c) for c in control_id_filter if c}
            fw_value = scan.framework.value if hasattr(scan.framework, "value") else (scan.framework or "")

            def _matches(f) -> bool:
                # Direct control_id match (after normalize)
                if f.control_id and _norm_ctrl(f.control_id) in wanted:
                    return True
                # Cross-framework mapping
                mappings = getattr(f, "control_mappings", {}) or {}
                if fw_value and isinstance(mappings, dict):
                    for cid in mappings.get(fw_value, []) or []:
                        if cid and _norm_ctrl(cid) in wanted:
                            return True
                return False

            all_findings = [f for f in all_findings if _matches(f)]

        # Persist raw findings
        for f in all_findings:
            finding = Finding(
                scan_id=scan_id,
                title=f.title,
                description=f.description,
                severity=f.severity.value,
                resource_id=f.resource_id,
                resource_type=f.resource_type,
                control_id=f.control_id,
                framework=scan.framework,
                remediation=f.remediation,
                evidence=f.evidence,
                cve_id=f.cve_id,
                cvss_score=f.cvss_score or None,
                control_mappings=getattr(f, "control_mappings", {}) or {},
            )
            db.add(finding)
        db.commit()

        # Run AI agents orchestration
        client = db.query(Client).filter(Client.id == scan.client_id).first()
        findings_dicts = [
            {
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "control_id": f.control_id,
                "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
            }
            for f in all_findings
        ]
        agent_report = await _get_orchestrator().run_full_assessment(
            findings_dicts,
            client.name if client else "Unknown",
            scan.framework or "nist_csf",
            scan.id,
        )

        # Persist agent run record
        agent_run = AgentRun(
            client_id=scan.client_id,
            agent_type=AgentType.ORCHESTRATOR,
            scan_id=scan.id,
            status="completed",
            output_data=agent_report,
        )
        agent_run.completed_at = datetime.now(timezone.utc)
        db.add(agent_run)

        # Summary
        sev_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
        for f in all_findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        scan.summary = {**sev_counts, "total": len(all_findings)}
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()

        # Re-derive framework compliance from the new findings
        try:
            from api.models.models import FrameworkType, ConnectorType
            from services.compliance import apply_defender_evaluations
            scan_fw = None
            if scan.framework:
                fw_value = scan.framework.value if hasattr(scan.framework, "value") else str(scan.framework)
                scan_fw = FrameworkType(fw_value)

            # Try Defender for Cloud regulatoryCompliance pull first — it gives
            # us the entire benchmark (every control evaluated by Microsoft) in
            # one shot. Falls back to per-finding recompute if unavailable.
            defender_used = False
            if scan_fw and scan.connector_id:
                connector_db_d = db.query(Connector).filter(Connector.id == scan.connector_id).first()
                if connector_db_d and (
                    connector_db_d.connector_type.value
                    if hasattr(connector_db_d.connector_type, "value")
                    else connector_db_d.connector_type
                ) == "azure":
                    try:
                        from connectors.azure.defender_compliance import get_regulatory_compliance
                        creds_d = json.loads(decrypt(connector_db_d.credentials_enc))
                        evaluations = await get_regulatory_compliance(creds_d, scan_fw.value)
                        if evaluations:
                            apply_defender_evaluations(db, scan.client_id, scan_fw, evaluations)
                            defender_used = True
                    except Exception as exc:
                        import logging as _lg
                        _lg.getLogger(__name__).warning("Defender pull failed: %s", exc)

            if not defender_used:
                if scan_fw:
                    recompute_client_framework(db, scan.client_id, scan_fw)
                else:
                    recompute_all_frameworks_for_client(db, scan.client_id)
        except Exception as exc:
            import logging as _lg
            _lg.getLogger(__name__).warning("Post-scan compliance recompute failed: %s", exc)

    except Exception as exc:
        db = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
        db.close()
    finally:
        db.close()


@router.post("/", response_model=ScanResponse, status_code=201)
async def start_scan(
    client_id: str,
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    # Infer project_id from connector if not explicitly provided
    proj_id = payload.project_id
    if not proj_id and payload.connector_id:
        c = db.query(Connector).filter(Connector.id == payload.connector_id).first()
        if c:
            proj_id = c.project_id
    scan = Scan(
        client_id=client_id,
        project_id=proj_id,
        connector_id=payload.connector_id,
        name=(payload.name or "").strip() or None,
        scan_type=payload.scan_type,
        framework=payload.framework,
        initiated_by=user.get("upn", user.get("preferred_username", "system")),
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    from core.config import get_settings
    background_tasks.add_task(
        _execute_scan, scan.id, get_settings().DATABASE_URL, None, payload.control_ids,
    )
    return scan


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    client_id: str,
    project_id: str = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(Scan).filter(Scan.client_id == client_id)
    if project_id:
        q = q.filter(Scan.project_id == project_id)
    return q.order_by(Scan.created_at.desc()).limit(50).all()


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(client_id: str, scan_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.client_id == client_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/findings/", response_model=List[FindingResponse])
async def get_findings(
    client_id: str,
    scan_id: str,
    severity: str = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    return q.order_by(Finding.cvss_score.desc()).all()


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    client_id: str,
    scan_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.client_id == client_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)  # cascade removes findings
    db.commit()


@router.patch("/{scan_id}/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    client_id: str, scan_id: str, finding_id: str,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    f = db.query(Finding).filter(Finding.id == finding_id, Finding.scan_id == scan_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(f, k, v)
    db.commit()
    db.refresh(f)
    if f.framework:
        from api.models.models import FrameworkType as _FT
        try:
            fv = f.framework.value if hasattr(f.framework, "value") else str(f.framework)
            recompute_client_framework(db, client_id, _FT(fv))
        except Exception:
            pass
    return f
