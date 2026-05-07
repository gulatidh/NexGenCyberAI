"""Scan management and execution endpoints."""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone
import json
from api.models.models import Scan, ScanStatus, Finding, Connector, FrameworkAssessment, AgentRun, AgentType
from api.schemas.schemas import ScanCreate, ScanResponse, FindingResponse, FindingUpdate
from db.database import get_db
from core.security import get_current_user
from core.encryption import decrypt
from connectors.factory import get_connector
from agents.orchestrator.orchestrator import AgentOrchestrator

router = APIRouter(prefix="/clients/{client_id}/scans", tags=["scans"])
orchestrator = AgentOrchestrator()


async def _execute_scan(scan_id: str, db_url: str):
    """Background task: run the scan and populate findings."""
    from ...db.database import SessionLocal
    from ...api.models.models import Client, ScanType
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
                creds = json.loads(decrypt(connector_db.credentials_enc))
                connector = get_connector(connector_db.connector_type, creds, connector_db.config or {})
                if scan.scan_type in ("vulnerability", "full"):
                    vuln_findings = await connector.run_vulnerability_scan()
                    all_findings.extend(vuln_findings)
                if scan.scan_type in ("configuration", "compliance", "full"):
                    config_findings = await connector.run_configuration_review()
                    all_findings.extend(config_findings)

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
        agent_report = await orchestrator.run_full_assessment(
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
    scan = Scan(
        client_id=client_id,
        connector_id=payload.connector_id,
        scan_type=payload.scan_type,
        framework=payload.framework,
        initiated_by=user.get("upn", user.get("preferred_username", "system")),
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    from ...core.config import get_settings
    background_tasks.add_task(_execute_scan, scan.id, get_settings().DATABASE_URL)
    return scan


@router.get("/", response_model=List[ScanResponse])
async def list_scans(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(Scan).filter(Scan.client_id == client_id).order_by(Scan.created_at.desc()).limit(50).all()


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
    return f
