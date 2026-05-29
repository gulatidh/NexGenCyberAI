"""Public endpoints used by the ZAP runner workflow.

These are NOT under the /clients/{client_id} prefix because the workflow
has no user bearer — it authenticates with a per-scan HMAC token.

  GET  /scans/config/?scan_id=...&scan_token=...   → workflow reads this
  POST /scans/ingest/                              → workflow posts findings
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi import Depends

from api.models.models import Finding, Scan, ScanStatus
from db.database import get_db
from core.scan_tokens import verify_scan_token
from services.scan_runtime import get_runtime, clear_runtime

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scans-runner"])


# ── GET /scans/config/ ───────────────────────────────────────────────────────

@router.get("/scans/config/")
async def get_scan_runtime_config(
    scan_id: str = Query(...),
    scan_token: str = Query(...),
    db: Session = Depends(get_db),
):
    """Workflow fetches what to scan + the prepared auth/credentials.

    For ZAP scans the runtime store has prepared auth_headers + target_url.
    For workflow-based scanners (Trivy/Gitleaks/TruffleHog/...) we also
    surface the connector's config + selected credential fields (repo_url,
    image, target, git_username, git_token, sonar_*) so workflows can
    clone private repos and scan the right target. The HMAC scan_token
    gates access, so secrets only leave the API for an authorized scan.
    """
    if verify_scan_token(scan_token, expected_scan_id=scan_id) is None:
        raise HTTPException(status_code=401, detail="Invalid or expired scan token")
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    runtime = get_runtime(scan_id) or {}

    # Pull connector config + credentials when the scan is tied to a
    # connector — workflow scanners read fields like repo_url from here.
    connector_fields: Dict[str, Any] = {}
    if scan.connector_id:
        import json
        from api.models.models import Connector
        from core.encryption import decrypt
        c = db.query(Connector).filter(Connector.id == scan.connector_id).first()
        if c:
            cfg = c.config or {}
            try:
                creds = json.loads(decrypt(c.credentials_enc)) if c.credentials_enc else {}
            except Exception:
                creds = {}
            # Whitelist fields the workflows actually need
            for key in (
                "repo_url", "image", "target",
                "git_username", "git_token",
                "sonar_host_url", "sonar_project_key", "sonar_token",
            ):
                v = cfg.get(key) or creds.get(key)
                if v:
                    connector_fields[key] = v

    return {
        "scan_id": scan_id,
        "target_url": runtime.get("target_url"),
        "profile": runtime.get("profile") or "baseline",
        "auth_headers": runtime.get("auth_headers") or {},
        "exclude_paths": runtime.get("exclude_paths") or [],
        # Workflow-scanner fields (private repo auth, target image, etc.)
        **connector_fields,
    }


# ── POST /scans/ingest/ ──────────────────────────────────────────────────────

class IngestFinding(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "info"  # critical | high | medium | low | info
    resource_id: Optional[str] = None
    resource_type: Optional[str] = "web/endpoint"
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    control_id: Optional[str] = None  # e.g. CWE-79, OWASP-A03:2021
    remediation: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    control_mappings: Optional[Dict[str, List[str]]] = None  # {"nist_800_53": ["SI-10"], ...}


class IngestPayload(BaseModel):
    scan_id: str
    scan_token: str
    findings: List[IngestFinding] = []
    error: Optional[str] = None  # if set, scan is marked failed
    summary: Optional[Dict[str, Any]] = None


_VALID_SEV = {"critical", "high", "medium", "low", "info"}


@router.post("/scans/ingest/")
async def ingest_scan_results(payload: IngestPayload = Body(...), db: Session = Depends(get_db)):
    """Workflow posts findings here when it finishes (or on error)."""
    if verify_scan_token(payload.scan_token, expected_scan_id=payload.scan_id) is None:
        raise HTTPException(status_code=401, detail="Invalid or expired scan token")
    scan = db.query(Scan).filter(Scan.id == payload.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if payload.error:
        scan.status = ScanStatus.FAILED
        scan.error_message = payload.error[:500]
        scan.completed_at = datetime.now(timezone.utc)
        clear_runtime(payload.scan_id)
        db.commit()
        return {"ok": True, "status": "failed"}

    sev_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    for f in payload.findings:
        sev = (f.severity or "info").lower()
        if sev not in _VALID_SEV:
            sev = "info"
        finding = Finding(
            scan_id=scan.id,
            title=f.title[:255] if f.title else "(untitled)",
            description=f.description,
            severity=sev,
            resource_id=f.resource_id,
            resource_type=f.resource_type or "web/endpoint",
            control_id=f.control_id,
            framework=scan.framework,
            remediation=f.remediation,
            evidence=f.evidence or {},
            cve_id=f.cve_id,
            cvss_score=f.cvss_score,
            control_mappings=f.control_mappings or {},
        )
        db.add(finding)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    scan.summary = {**(scan.summary or {}), **sev_counts, "total": len(payload.findings)}
    scan.summary.pop("runtime", None)  # secrets — wipe after ingest
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()
    clear_runtime(payload.scan_id)

    # Recompute frameworks once findings are persisted.
    try:
        from services.compliance import recompute_all_frameworks_for_client
        recompute_all_frameworks_for_client(db, scan.client_id)
    except Exception as exc:
        logger.warning("Post-ingest recompute failed: %s", exc)

    return {"ok": True, "status": "completed", "ingested": len(payload.findings)}
