"""Scan management and execution endpoints."""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
import json
from api.models.models import Scan, ScanStatus, Finding, Connector, FrameworkAssessment, AgentRun, AgentType
from api.schemas.schemas import ScanCreate, ScanResponse, FindingResponse, FindingUpdate
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere
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

        # AI Code Review with no connector — repo URL + optional token supplied
        # inline at scan-creation time (stored in scan.summary).
        _summary = scan.summary or {}
        if not scan.connector_id and (_summary.get("repo_url") or _summary.get("code_archive")):
            from core.config import get_settings as _gs
            from core.encryption import decrypt as _dec
            from services.code_review import run_ai_code_review
            _repo_url = _summary.get("repo_url") or ""
            _archive = _summary.get("code_archive") or ""
            _git_token_enc = _summary.get("git_token_enc") or ""
            _git_token = ""
            if _git_token_enc:
                try:
                    _git_token = _dec(_git_token_enc)
                except Exception:
                    pass
            await run_ai_code_review(
                scan_id=scan.id,
                db_url=_gs().DATABASE_URL,
                repo_url=_repo_url or None,
                archive_path=_archive or None,
                git_token=_git_token,
            )
            return

        if scan.connector_id:
            connector_db = db.query(Connector).filter(Connector.id == scan.connector_id).first()
            if connector_db:
                # Web (ZAP) connector: dispatch a GitHub workflow and exit
                # early — findings come back later via /scans/ingest/.
                from api.models.models import ConnectorType as _CT
                ctype = connector_db.connector_type
                ctype_value = ctype.value if hasattr(ctype, "value") else str(ctype)

                # Enterprise professional scanners — direct API (no GitHub Actions)
                _ENTERPRISE_SCANNER_TYPES = {
                    _CT.TENABLE.value, _CT.BURP_ENTERPRISE.value, _CT.SNYK.value,
                    _CT.RAPID7.value, _CT.QUALYS.value, _CT.INVICTI.value, _CT.ACUNETIX.value,
                }
                if ctype_value in _ENTERPRISE_SCANNER_TYPES:
                    from services.scanners import run_enterprise_scan
                    _ent_creds = json.loads(decrypt(connector_db.credentials_enc)) if connector_db.credentials_enc else {}
                    _ent_cfg = connector_db.config or {}
                    await run_enterprise_scan(ctype_value, scan.id, db_url, _ent_creds, _ent_cfg)
                    return

                if ctype_value == _CT.WEB.value:
                    from connectors.web.connector import trigger_zap_scan
                    from api.models.models import FrameworkType
                    creds = json.loads(decrypt(connector_db.credentials_enc))
                    cfg = connector_db.config or {}
                    profile = (scan.summary or {}).get("requested_profile") or cfg.get("default_profile") or "baseline"
                    target_url = cfg.get("target_url", "")
                    auth = creds.get("auth", {"method": "none"})
                    # Auto-tag the scan's framework based on profile + auth so
                    # ZAP findings land in the right compliance catalog.
                    if not scan.framework:
                        auth_method = (auth or {}).get("method", "none")
                        if profile == "active":
                            scan.framework = FrameworkType.ZAP_AUTH_ACTIVE
                        else:
                            # baseline (passive) — auth or unauth both land here
                            scan.framework = FrameworkType.ZAP_UNAUTH_PASSIVE
                        db.commit()
                    result = trigger_zap_scan(
                        scan_id=scan.id,
                        target_url=target_url,
                        auth=auth,
                        profile=profile,
                        exclude_paths=cfg.get("exclude_paths") or [],
                    )
                    if not result.get("ok"):
                        scan.status = ScanStatus.FAILED
                        scan.error_message = f"Workflow dispatch failed: {result.get('error')}"
                        scan.completed_at = datetime.now(timezone.utc)
                        db.commit()
                    # Stay in RUNNING — workflow will mark COMPLETED via ingest.
                    return

                # Generic WorkflowConnector path — any scanner that defers
                # execution to a GitHub Actions workflow (NMAP, Trivy,
                # Gitleaks, TruffleHog, Semgrep, ...). Dispatch the
                # workflow, persist its runtime target, and stay in
                # RUNNING until /scans/ingest/ is called by the runner.
                try:
                    from connectors.scanners.base import WorkflowConnector
                    creds = json.loads(decrypt(connector_db.credentials_enc)) if connector_db.credentials_enc else {}
                    conn_obj = get_connector(connector_db.connector_type, creds, connector_db.config or {})
                except Exception:
                    conn_obj = None

                # AI Code Review — runs fully local, no GitHub Actions needed
                if ctype_value == _CT.AI_CODE_REVIEW.value:
                    from core.config import get_settings as _gs
                    from services.code_review import run_ai_code_review
                    creds = json.loads(decrypt(connector_db.credentials_enc)) if connector_db.credentials_enc else {}
                    cfg = connector_db.config or {}
                    repo_url = (scan.summary or {}).get("repo_url") or creds.get("repo_url") or cfg.get("repo_url") or ""
                    git_username = creds.get("git_username") or cfg.get("git_username") or ""
                    git_token = creds.get("git_token") or cfg.get("git_token") or ""
                    archive_path = (scan.summary or {}).get("code_archive") or ""
                    import asyncio as _aio
                    await run_ai_code_review(
                        scan_id=scan.id,
                        db_url=_gs().DATABASE_URL,
                        repo_url=repo_url or None,
                        archive_path=archive_path or None,
                        git_username=git_username,
                        git_token=git_token,
                    )
                    return

                if isinstance(conn_obj, WorkflowConnector) and conn_obj.WORKFLOW_FILE:
                    from core.scan_tokens import mint_scan_token
                    from core.github_dispatch import dispatch_workflow
                    from services.scan_runtime import set_runtime
                    import os as _os

                    target = conn_obj._primary_target()
                    # Binary-mode scans don't need a target from the connector
                    # config — the uploaded binary is the target. Its presence
                    # is recorded on scan.summary["binary"] by the upload
                    # endpoint.
                    has_binary = bool((scan.summary or {}).get("binary"))
                    if not target and not has_binary:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = (
                            f"Cannot start {connector_db.connector_type} scan — missing "
                            f"required config (need one of: {', '.join(conn_obj.REQUIRED_CONFIG)}) "
                            "or an uploaded binary."
                        )
                        scan.completed_at = datetime.now(timezone.utc)
                        db.commit()
                        return

                    scan_token = mint_scan_token(scan.id)
                    set_runtime(scan.id, {
                        # Surface every key the workflow runner might read via
                        # /scans/config/. Workflows ignore fields they don't use.
                        "target": target,
                        "repo_url": conn_obj._get("repo_url") or None,
                        "image": conn_obj._get("image") or None,
                        "git_username": conn_obj._get("git_username") or None,
                        "git_token": conn_obj._get("git_token") or None,
                    })

                    inputs = {
                        "scan_id": scan.id,
                        "scan_token": scan_token,
                        "api_base": (_os.environ.get("PUBLIC_API_BASE") or "").rstrip("/"),
                    }
                    result = dispatch_workflow(conn_obj.WORKFLOW_FILE, inputs)
                    if not result.get("ok"):
                        scan.status = ScanStatus.FAILED
                        scan.error_message = f"Workflow dispatch failed: {result.get('error')}"
                        scan.completed_at = datetime.now(timezone.utc)
                        db.commit()
                    # Else: stay in RUNNING — workflow will mark COMPLETED via ingest.
                    return

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

                # Collect raw resource inventory for agent context
                try:
                    resources = await connector.get_resources()
                    if resources:
                        scan.raw_context = json.dumps(resources[:200])  # cap at 200 resources — configs are larger now
                        db.commit()
                except Exception as _rc_exc:
                    import logging as _lg
                    _lg.getLogger(__name__).debug("Resource inventory collection failed: %s", _rc_exc)

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


@router.post("/", response_model=ScanResponse, status_code=201, dependencies=[Depends(require_editor_anywhere)])
async def start_scan(
    client_id: str,
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    from core.trial import get_trial, check_scan_limit, is_admin
    if not is_admin(user):
        trial = get_trial(db, user)
        check_scan_limit(db, trial, client_id)

    # Infer project_id from connector if not explicitly provided
    proj_id = payload.project_id
    if not proj_id and payload.connector_id:
        c = db.query(Connector).filter(Connector.id == payload.connector_id).first()
        if c:
            proj_id = c.project_id
    # Default the name to "<scan_type>_<date>_<time>" so unnamed scans are
    # distinguishable instead of all reading as just "full".
    _st = payload.scan_type.value if hasattr(payload.scan_type, "value") else str(payload.scan_type or "scan")
    _default_name = f"{_st}_{datetime.now(timezone.utc):%Y%m%d_%H%M}"
    initial_summary: dict | None = None
    if payload.repo_url or payload.git_token:
        from core.encryption import encrypt as _enc
        initial_summary = {}
        if payload.repo_url:
            initial_summary["repo_url"] = payload.repo_url
        if payload.git_token:
            initial_summary["git_token_enc"] = _enc(payload.git_token)
    scan = Scan(
        client_id=client_id,
        project_id=proj_id,
        connector_id=payload.connector_id,
        name=(payload.name or "").strip() or _default_name,
        scan_type=payload.scan_type,
        framework=payload.framework,
        initiated_by=user.get("upn", user.get("preferred_username", "system")),
        status=ScanStatus.PENDING,
        summary=initial_summary,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    if not payload.defer_dispatch:
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


@router.post("/{scan_id}/upload-code/", dependencies=[Depends(require_editor_anywhere)])
async def upload_code_archive(
    client_id: str,
    scan_id: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """
    Upload a zip or tar.gz code archive for an AI Code Review scan.
    Stores the file, records its path on the scan, then fires the review
    pipeline as a background task.
    """
    import os
    import aiofiles

    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.client_id == client_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    fname = file.filename or "archive.zip"
    if fname.endswith(".zip"):
        ext = ".zip"
    elif fname.endswith(".tar.gz") or fname.endswith(".tgz"):
        ext = ".tar.gz"
    elif fname.endswith(".tar"):
        ext = ".tar"
    else:
        raise HTTPException(status_code=400, detail="Only .zip, .tar.gz, and .tar archives are supported")

    # /home persists across container restarts on App Service; /tmp is wiped.
    os.makedirs("/home/code_review", exist_ok=True)
    dest = f"/home/code_review/{scan_id}{ext}"

    try:
        async with aiofiles.open(dest, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                await out.write(chunk)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Upload failed: {exc}")

    existing_summary = scan.summary or {}
    scan.summary = {**existing_summary, "code_archive": dest}
    db.commit()

    # Fire the AI code review pipeline
    from core.config import get_settings as _gs
    from services.code_review import run_ai_code_review
    background_tasks.add_task(
        run_ai_code_review,
        scan_id=scan_id,
        db_url=_gs().DATABASE_URL,
        repo_url=None,
        archive_path=dest,
    )

    return {"status": "uploaded", "path": dest, "scan_id": scan_id}


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


@router.post("/{scan_id}/rescan", response_model=ScanResponse, status_code=201, dependencies=[Depends(require_editor_anywhere)])
async def rescan(
    client_id: str,
    scan_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Create a new scan that duplicates an existing scan's configuration
    (connector, scan_type, framework, name). Sets parent_scan_id on the new
    scan so the UI can render version history for the target.

    Works on completed, failed, or even running scans — every rescan is a
    fresh row, the old one stays as-is for history."""
    original = db.query(Scan).filter(Scan.id == scan_id, Scan.client_id == client_id).first()
    if not original:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Walk to the root of the rescan chain so version history is flat —
    # every rescan points at the original scan, not the immediately
    # previous one. Simpler to render N versions when they're all siblings.
    root_id = original.parent_scan_id or original.id

    # For archive-upload scans (ai_code_review) carry the archive path forward
    # so the rescan has a source to work from.
    inherited_summary: dict = {}
    orig_summary = original.summary or {}
    if orig_summary.get("code_archive"):
        inherited_summary["code_archive"] = orig_summary["code_archive"]
    if orig_summary.get("repo_url"):
        inherited_summary["repo_url"] = orig_summary["repo_url"]
    if orig_summary.get("git_token_enc"):
        inherited_summary["git_token_enc"] = orig_summary["git_token_enc"]

    new = Scan(
        client_id=client_id,
        project_id=original.project_id,
        connector_id=original.connector_id,
        name=original.name,
        scan_type=original.scan_type,
        framework=original.framework,
        initiated_by=user.get("upn", user.get("preferred_username", "system")),
        status=ScanStatus.PENDING,
        parent_scan_id=root_id,
        summary=inherited_summary or None,
    )
    db.add(new)
    db.commit()
    db.refresh(new)
    from core.config import get_settings
    background_tasks.add_task(
        _execute_scan, new.id, get_settings().DATABASE_URL, None, None,
    )
    return new


@router.get("/{scan_id}/versions", response_model=List[ScanResponse])
async def list_scan_versions(
    client_id: str,
    scan_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Every scan that shares the same root with this one — i.e. the
    original scan + every rescan of it. Newest first."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.client_id == client_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    root_id = scan.parent_scan_id or scan.id
    return (
        db.query(Scan)
        .filter(Scan.client_id == client_id)
        .filter((Scan.id == root_id) | (Scan.parent_scan_id == root_id))
        .order_by(Scan.created_at.desc())
        .all()
    )


@router.post("/{scan_id}/upload-binary", status_code=201, dependencies=[Depends(require_editor_anywhere)])
async def upload_scan_binary(
    client_id: str,
    scan_id: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Upload a compiled artifact (JAR / WAR / DLL / EAR / tar.gz / zip)
    that the workflow runner will scan with `codeql database create
    --mode=none`. The file is stored on the App Service `/home/data/`
    mount (persistent across restarts) and the workflow fetches it via
    `GET /scans/binary/{scan_id}` with the per-scan HMAC token.

    Auto-deleted after 30 days. After the upload succeeds, the scan's
    dispatch fires (the scan is left in PENDING by the create call when
    a binary is expected — that handshake is what makes the workflow
    only run after the binary is actually on disk)."""
    from services.scan_binaries import save_upload

    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.client_id == client_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # 500 MB hard limit to protect /home/ disk. App Service Basic = 1 GB.
    MAX_BYTES = 500 * 1024 * 1024

    def _chunks():
        total = 0
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                raise HTTPException(status_code=413, detail="Binary exceeds 500 MB limit")
            yield chunk

    try:
        meta = save_upload(scan_id, file.filename or "binary.bin", _chunks())
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Upload failed: {exc}")

    # Stash filename + sha on the scan so /scans/config/ can advertise it
    # to the workflow runner.
    summary = dict(scan.summary or {})
    summary["binary"] = {
        "filename": meta["filename"],
        "size": meta["size"],
        "sha256": meta["sha256"],
        "uploaded_at": meta["uploaded_at"],
    }
    scan.summary = summary
    db.commit()

    # Now that the binary is on disk, fire the workflow.
    from core.config import get_settings
    background_tasks.add_task(
        _execute_scan, scan.id, get_settings().DATABASE_URL, None, None,
    )
    return {"ok": True, **meta, "scan_id": scan_id}


@router.get("/coverage-gaps/")
async def get_coverage_gaps(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return resources from the latest scan's raw_context that have no associated findings.

    These are 'unseen' assets — discovered during enumeration but never triggered a rule.
    The AI agents couldn't reason about them before raw_context was introduced.
    """
    # Get the latest completed scan with raw_context for this client
    latest_scan = (
        db.query(Scan)
        .filter(
            Scan.client_id == client_id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .order_by(Scan.completed_at.desc())
        .first()
    )

    if not latest_scan:
        return {"scan_id": None, "covered": [], "uncovered": [], "summary": {"total": 0, "covered": 0, "uncovered": 0}}

    raw_ctx = getattr(latest_scan, "raw_context", None)
    if not raw_ctx:
        return {
            "scan_id": latest_scan.id,
            "covered": [],
            "uncovered": [],
            "summary": {
                "total": 0,
                "covered": 0,
                "uncovered": 0,
                "message": "No resource inventory available — re-run the scan to collect it",
            },
        }

    try:
        resources = json.loads(raw_ctx)
    except Exception:
        resources = []

    # Get all resource_ids from findings for this scan
    findings = db.query(Finding).filter(Finding.scan_id == latest_scan.id).all()
    finding_resource_ids = {(f.resource_id or "").lower() for f in findings if f.resource_id}

    covered = []
    uncovered = []
    for r in resources:
        rid = (r.get("id") or r.get("resource_id") or "").lower()
        if rid and any(rid in frid or frid in rid for frid in finding_resource_ids):
            covered.append(r)
        else:
            uncovered.append(r)

    return {
        "scan_id": latest_scan.id,
        "summary": {
            "total": len(resources),
            "covered": len(covered),
            "uncovered": len(uncovered),
            "coverage_pct": round(len(covered) / len(resources) * 100) if resources else 0,
        },
        "covered": covered[:100],    # cap for API response size
        "uncovered": uncovered[:200],
    }


@router.get("/{scan_id}/diff")
async def get_scan_diff(
    client_id: str,
    scan_id: str,
    compare_with: Optional[str] = None,  # scan_id of the "base" scan to compare against
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Compare two scans and return new/resolved/persisting findings.

    If compare_with is not provided, uses scan.parent_scan_id.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.client_id == client_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    base_id = compare_with or getattr(scan, "parent_scan_id", None)
    if not base_id:
        raise HTTPException(
            status_code=422,
            detail="No base scan to compare against. Provide compare_with= or re-scan (which auto-sets parent_scan_id).",
        )

    base_scan = db.query(Scan).filter(Scan.id == base_id, Scan.client_id == client_id).first()
    if not base_scan:
        raise HTTPException(status_code=404, detail="Base scan not found")

    current_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    base_findings = db.query(Finding).filter(Finding.scan_id == base_id).all()

    # Key findings by (title, resource_id) for matching
    def _key(f):
        return (f.title.strip().lower(), (f.resource_id or "").strip().lower())

    current_keys = {_key(f): f for f in current_findings}
    base_keys = {_key(f): f for f in base_findings}

    new_findings = [f for k, f in current_keys.items() if k not in base_keys]
    resolved_findings = [f for k, f in base_keys.items() if k not in current_keys]
    persisting_findings = [f for k, f in current_keys.items() if k in base_keys]

    def _serialize(f):
        return {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "control_id": f.control_id,
            "description": f.description,
        }

    return {
        "scan_id": scan_id,
        "base_scan_id": base_id,
        "scan_completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "base_scan_completed_at": base_scan.completed_at.isoformat() if base_scan.completed_at else None,
        "summary": {
            "new": len(new_findings),
            "resolved": len(resolved_findings),
            "persisting": len(persisting_findings),
            "total_current": len(current_findings),
            "total_base": len(base_findings),
        },
        "new_findings": [_serialize(f) for f in new_findings],
        "resolved_findings": [_serialize(f) for f in resolved_findings],
        "persisting_findings": [_serialize(f) for f in persisting_findings],
    }


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
