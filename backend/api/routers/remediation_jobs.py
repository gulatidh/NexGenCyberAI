"""Fix with AI — remediation job lifecycle endpoints."""
import logging
import uuid
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel

from db.database import SessionLocal, engine
from api.models.models import RemediationJob, RemediationJobStatus, Finding, Scan, ScanStatus, ScanType, Connector
from core.security import get_current_user
from core.authz import require_scoped_role, AccessRole, AccessScope

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/clients/{client_id}/remediation-jobs", tags=["remediation-jobs"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class RemediationJobCreate(BaseModel):
    finding_ids: List[str]
    scan_id: Optional[str] = None


class RemediationJobResponse(BaseModel):
    id: str
    client_id: str
    scan_id: Optional[str]
    finding_ids: List[str]
    status: str
    plans: Optional[List[dict]] = None
    overall_summary: Optional[str] = None
    overall_confidence: Optional[float] = None
    overall_risk_level: Optional[str] = None
    recommended_order: Optional[List[str]] = None
    verification_scan_id: Optional[str] = None
    verification_results: Optional[dict] = None
    error_message: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── Background task: run planner ─────────────────────────────────────────────

async def _run_planner(job_id: str):
    from services.remediation_executor.planner import generate_remediation_plan

    db = SessionLocal()
    try:
        job = db.query(RemediationJob).filter(RemediationJob.id == job_id).first()
        if not job:
            return

        job.status = RemediationJobStatus.ANALYZING
        db.commit()

        findings = (
            db.query(Finding)
            .filter(Finding.id.in_(job.finding_ids))
            .all()
        )
        if not findings:
            job.status = RemediationJobStatus.FAILED
            job.error_message = "No findings found for the provided IDs."
            db.commit()
            return

        plan = await generate_remediation_plan(findings)

        # Attach finding title/severity to each plan item so the UI can display
        # the title even when the Finding objects are not passed to the dialog.
        finding_meta = {str(f.id): (f.title, f.severity.value if hasattr(f.severity, "value") else str(f.severity)) for f in findings}
        enriched_plans = []
        for p in plan.get("findings", []):
            fid = p.get("finding_id", "")
            title, sev = finding_meta.get(fid, (None, None))
            enriched = {**p}
            if title:
                enriched["finding_title"] = title
            if sev:
                enriched["finding_severity"] = sev
            enriched_plans.append(enriched)

        job.plans = enriched_plans
        job.overall_summary = plan.get("overall_summary")
        job.overall_confidence = plan.get("overall_confidence")
        job.overall_risk_level = plan.get("overall_risk_level")
        job.recommended_order = plan.get("recommended_order", [])
        job.status = RemediationJobStatus.READY
        db.commit()
        logger.info("RemediationJob %s ready — %d finding plans", job_id, len(job.plans or []))

    except Exception as exc:
        logger.error("RemediationJob %s planner failed: %s", job_id, exc, exc_info=True)
        db.rollback()
        job = db.query(RemediationJob).filter(RemediationJob.id == job_id).first()
        if job:
            job.status = RemediationJobStatus.FAILED
            job.error_message = str(exc)[:500]
            db.commit()
    finally:
        db.close()


# ── Background task: verification rescan ─────────────────────────────────────

async def _run_verification(job_id: str):
    """Trigger a rescan and diff findings to verify remediation."""
    import asyncio
    from api.routers.scans import _execute_scan

    db = SessionLocal()
    try:
        job = db.query(RemediationJob).filter(RemediationJob.id == job_id).first()
        if not job or not job.scan_id:
            return

        original_scan = db.query(Scan).filter(Scan.id == job.scan_id).first()
        if not original_scan or not original_scan.connector_id:
            job.status = RemediationJobStatus.FAILED
            job.error_message = "Cannot verify: original scan has no connector."
            db.commit()
            return

        # Create verification scan
        v_scan = Scan(
            id=str(uuid.uuid4()),
            client_id=job.client_id,
            connector_id=original_scan.connector_id,
            project_id=original_scan.project_id,
            scan_type=original_scan.scan_type,
            status=ScanStatus.PENDING,
            name=f"Verification scan for remediation job {job_id[:8]}",
            target=original_scan.target,
            framework=original_scan.framework,
            is_live=True,
        )
        db.add(v_scan)
        job.verification_scan_id = v_scan.id
        job.status = RemediationJobStatus.VERIFYING
        db.commit()

        # Run the scan (this is async, up to 2 hours for enterprise scanners)
        await _execute_scan(v_scan.id, str(engine.url))

        # Once scan completes, diff findings
        db.expire_all()
        v_scan = db.query(Scan).filter(Scan.id == v_scan.id).first()
        if not v_scan or v_scan.status != ScanStatus.COMPLETED:
            job.status = RemediationJobStatus.FAILED
            job.error_message = "Verification scan did not complete successfully."
            db.commit()
            return

        # Build a lookup of new findings by (title, resource_id)
        new_findings = db.query(Finding).filter(Finding.scan_id == v_scan.id).all()
        new_keys = {(f.title.lower().strip(), (f.resource_id or "").lower().strip()) for f in new_findings}

        # Check each original finding
        original_findings = db.query(Finding).filter(Finding.id.in_(job.finding_ids)).all()
        results = {}
        resolved_count = 0
        for f in original_findings:
            key = (f.title.lower().strip(), (f.resource_id or "").lower().strip())
            if key not in new_keys:
                results[str(f.id)] = "resolved"
                # Mark the original finding as remediated
                f.status = "remediated"
                f.remediated_at = datetime.now(timezone.utc)
                resolved_count += 1
            else:
                results[str(f.id)] = "unresolved"

        job.verification_results = results
        if resolved_count == len(original_findings):
            job.status = RemediationJobStatus.VERIFIED
        elif resolved_count > 0:
            job.status = RemediationJobStatus.PARTIAL
        else:
            job.status = RemediationJobStatus.UNRESOLVED
        db.commit()
        logger.info(
            "RemediationJob %s verification complete: %d/%d resolved",
            job_id, resolved_count, len(original_findings),
        )

    except Exception as exc:
        logger.error("RemediationJob %s verification failed: %s", job_id, exc, exc_info=True)
        db.rollback()
        job = db.query(RemediationJob).filter(RemediationJob.id == job_id).first()
        if job:
            job.status = RemediationJobStatus.FAILED
            job.error_message = f"Verification failed: {str(exc)[:400]}"
            db.commit()
    finally:
        db.close()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/", response_model=RemediationJobResponse, status_code=201)
async def create_remediation_job(
    client_id: str,
    payload: RemediationJobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)

    if not payload.finding_ids:
        raise HTTPException(status_code=400, detail="finding_ids must not be empty")
    if len(payload.finding_ids) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 findings per job")

    job = RemediationJob(
        id=str(uuid.uuid4()),
        client_id=client_id,
        scan_id=payload.scan_id,
        finding_ids=payload.finding_ids,
        status=RemediationJobStatus.PENDING,
        created_by=user.get("preferred_username") or user.get("email") or user.get("unique_name"),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    background_tasks.add_task(_run_planner, job.id)
    return job


@router.get("/", response_model=List[RemediationJobResponse])
def list_remediation_jobs(
    client_id: str,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    return (
        db.query(RemediationJob)
        .filter(RemediationJob.client_id == client_id)
        .order_by(RemediationJob.created_at.desc())
        .limit(100)
        .all()
    )


@router.get("/{job_id}", response_model=RemediationJobResponse)
def get_remediation_job(
    client_id: str,
    job_id: str,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    job = db.query(RemediationJob).filter(
        RemediationJob.id == job_id, RemediationJob.client_id == client_id
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found")
    return job


@router.post("/{job_id}/verify", response_model=RemediationJobResponse)
async def verify_remediation_job(
    client_id: str,
    job_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    job = db.query(RemediationJob).filter(
        RemediationJob.id == job_id, RemediationJob.client_id == client_id
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found")
    if job.status not in (RemediationJobStatus.READY, RemediationJobStatus.UNRESOLVED, RemediationJobStatus.PARTIAL):
        raise HTTPException(status_code=400, detail=f"Job is in '{job.status}' state — cannot verify now")
    if not job.scan_id:
        raise HTTPException(status_code=400, detail="No source scan linked — cannot auto-verify. Mark findings manually.")

    background_tasks.add_task(_run_verification, job.id)
    return job


@router.delete("/{job_id}", status_code=204)
def delete_remediation_job(
    client_id: str,
    job_id: str,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    job = db.query(RemediationJob).filter(
        RemediationJob.id == job_id, RemediationJob.client_id == client_id
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found")
    db.delete(job)
    db.commit()
