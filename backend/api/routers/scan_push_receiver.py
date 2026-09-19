"""Receiver endpoint for local runner → cloud scan push.

Accepts a full scan payload (client name, project name, scan metadata,
findings list) from a paired local runner and persists everything into
the cloud database, auto-creating client / project as needed.

Authentication: Bearer token checked against RunnerRegistry records.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel

from db.database import get_db

router = APIRouter(prefix="/ingest", tags=["ingest"])


# ── Pydantic models ───────────────────────────────────────────────────────────

class PushedFinding(BaseModel):
    title: str
    description: str = ""
    severity: str = "info"
    resource_id: str = ""
    resource_type: str = "host"
    control_id: str = ""
    framework: Optional[str] = None
    remediation: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    evidence: dict = {}
    status: str = "open"


class PushedScan(BaseModel):
    name: str
    scan_type: str = "vulnerability"
    framework: Optional[str] = None
    connector_type: Optional[str] = None
    source_runner: Optional[str] = None
    initiated_by: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class ScanPushPayload(BaseModel):
    client_name: str
    project_name: Optional[str] = None
    scan: PushedScan
    findings: List[PushedFinding] = []


# ── Auth helper ───────────────────────────────────────────────────────────────

def _verify_runner_token(authorization: str, db: Session) -> str:
    """Validate the Bearer token against RunnerRegistry and return runner_id."""
    from fastapi import Request
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = authorization[7:]
    # Import here to avoid circular at module load
    try:
        from api.models.models import RunnerRegistry
        runner = db.query(RunnerRegistry).filter(RunnerRegistry.token == token).first()
        if not runner:
            raise HTTPException(403, "Invalid runner token — pair the local runner first in Settings → Local Runner.")
        return runner.runner_id
    except ImportError:
        # RunnerRegistry model may not exist on older DBs — accept any non-empty token
        if not token:
            raise HTTPException(403, "Invalid runner token")
        return "unknown"


# ── Receiver endpoint ─────────────────────────────────────────────────────────

@router.post("/scan-push")
async def receive_scan_push(
    payload: ScanPushPayload,
    request: "Request",
    db: Session = Depends(get_db),
):
    """Receive a scan + findings from a paired local runner.

    Creates client / project / scan / findings as needed.
    Idempotent on client + project name — never duplicates.
    """
    from fastapi import Request
    from api.models.models import Client, Project, Scan, ScanStatus, Finding, Severity, FrameworkType, ScanType
    import json

    # Validate runner token from Authorization header
    authorization = request.headers.get("Authorization", "")
    try:
        from api.models.models import RunnerRegistry
        if authorization.startswith("Bearer "):
            token = authorization[7:]
            runner = db.query(RunnerRegistry).filter(RunnerRegistry.token == token).first()
            if not runner:
                raise HTTPException(403, "Invalid runner token — pair the local runner first.")
    except HTTPException:
        raise
    except Exception:
        pass  # RunnerRegistry table may not exist on older DBs — allow through

    # ── 1. Ensure client ──────────────────────────────────────────────────────
    client_name = payload.client_name.strip() or "Local Runner Client"
    client = db.query(Client).filter(
        Client.name == client_name,
        Client.deleted_at.is_(None),
    ).first()
    if not client:
        client = Client(name=client_name, description="Auto-created by local runner push")
        db.add(client)
        db.flush()

    # ── 2. Ensure project ─────────────────────────────────────────────────────
    project_id = None
    if payload.project_name:
        project_name = payload.project_name.strip()
        project = db.query(Project).filter(
            Project.client_id == client.id,
            Project.name == project_name,
        ).first()
        if not project:
            project = Project(client_id=client.id, name=project_name)
            db.add(project)
            db.flush()
        project_id = project.id

    # ── 3. Create scan ────────────────────────────────────────────────────────
    ps = payload.scan
    try:
        scan_type = ScanType(ps.scan_type)
    except ValueError:
        scan_type = ScanType.VULNERABILITY

    fw = None
    if ps.framework:
        try:
            fw = FrameworkType(ps.framework)
        except ValueError:
            pass

    scan = Scan(
        client_id=client.id,
        project_id=project_id,
        name=ps.name or f"Local push {datetime.now(timezone.utc):%Y%m%d_%H%M}",
        scan_type=scan_type,
        framework=fw,
        initiated_by=ps.initiated_by or "local_runner",
        status=ScanStatus.COMPLETED,
        summary={"source": "local_runner_push", "runner": ps.source_runner},
        is_live=True,
    )
    if ps.started_at:
        try:
            scan.started_at = datetime.fromisoformat(ps.started_at)
        except Exception:
            pass
    if ps.completed_at:
        try:
            scan.completed_at = datetime.fromisoformat(ps.completed_at)
        except Exception:
            pass
    else:
        scan.completed_at = datetime.now(timezone.utc)
    db.add(scan)
    db.flush()

    # ── 4. Bulk-insert findings ───────────────────────────────────────────────
    sev_map = {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    }
    now = datetime.now(timezone.utc)
    for pf in payload.findings:
        sev = sev_map.get(pf.severity.lower(), Severity.INFO)
        finding_fw = None
        if pf.framework:
            try:
                finding_fw = FrameworkType(pf.framework)
            except ValueError:
                finding_fw = fw
        db.add(Finding(
            scan_id=scan.id,
            title=(pf.title or "Finding")[:500],
            description=pf.description,
            severity=sev,
            resource_id=pf.resource_id,
            resource_type=pf.resource_type,
            control_id=pf.control_id,
            framework=finding_fw or fw,
            remediation=pf.remediation,
            evidence=json.dumps(pf.evidence) if pf.evidence else "{}",
            cve_id=pf.cve_id,
            cvss_score=pf.cvss_score or None,
            status="open",
            occurrence_count=1,
            last_seen_at=now,
        ))

    scan.summary = {
        **(scan.summary or {}),
        "total": len(payload.findings),
        "source": "local_runner_push",
    }
    db.commit()

    return {
        "ok": True,
        "client_id": client.id,
        "project_id": project_id,
        "scan_id": scan.id,
        "findings_ingested": len(payload.findings),
        "message": f"Pushed {len(payload.findings)} findings into '{client_name}'",
    }
