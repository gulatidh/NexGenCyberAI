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

from fastapi import APIRouter, BackgroundTasks, Body, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi import Depends

from api.models.models import (
    AssessmentImport, Connector, Finding, RawNmapFinding, RawTrivyFinding,
    RawZapFinding, RawSecretFinding, RawGenericFinding, Scan, ScanStatus,
)
from db.database import get_db
from core.scan_tokens import verify_scan_token
from services.scan_runtime import get_runtime, clear_runtime

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scans-runner"])


# ── Raw storage helpers ───────────────────────────────────────────────────────

def _safe_int(v):
    try: return int(v) if v is not None else None
    except: return None


def _safe_dt(v):
    if not v: return None
    if isinstance(v, datetime): return v
    try:
        from dateutil import parser as _dp
        return _dp.parse(str(v))
    except: return None


def _scanner_type_from_connector(db: Session, scan: Scan) -> str:
    """Determine scanner type string from scan's connector type."""
    if not scan.connector_id:
        return "generic"
    try:
        conn = db.query(Connector).filter(Connector.id == scan.connector_id).first()
        if not conn:
            return "generic"
        ct = conn.connector_type.value if hasattr(conn.connector_type, "value") else str(conn.connector_type)
        _map = {
            "nmap": "nmap", "web": "zap", "trivy": "trivy",
            "gitleaks": "gitleaks", "trufflehog": "trufflehog",
            "semgrep": "sarif", "codeql": "sarif", "sonarqube": "sarif",
            "owasp_dc": "generic", "nuclei": "generic",
        }
        return _map.get(ct, ct)
    except Exception:
        return "generic"


def _create_ingest_import(db: Session, scan: Scan, scanner_type: str, finding_count: int) -> Optional[int]:
    """Create an AssessmentImport record for a workflow-ingest scan. Returns import_id or None."""
    try:
        from sqlalchemy import func
        year = datetime.utcnow().year
        count = db.query(func.count(AssessmentImport.id)).filter(
            AssessmentImport.client_id == scan.client_id,
            func.extract("year", AssessmentImport.created_at) == year,
        ).scalar() or 0
        ai = AssessmentImport(
            client_id=scan.client_id,
            import_name=f"{scanner_type} scan – {scan.name or scan.id}",
            import_ref=f"IMP-{year}-{count + 1:03d}",
            scanner_type=scanner_type,
            detected_format=scanner_type,
            raw_finding_count=finding_count,
            normalized_finding_count=finding_count,
            created_at=datetime.utcnow(),
            scan_id=scan.id,
            status="completed",
        )
        db.add(ai)
        db.flush()
        return ai.id
    except Exception as exc:
        logger.warning("Could not create AssessmentImport for scan %s: %s", scan.id, exc)
        return None


def _insert_ingest_raw_row(db: Session, scanner_type: str, import_id: int, client_id: str,
                            f: "IngestFinding", finding_id: int) -> None:
    """Insert a raw row for a single ingested finding based on scanner_type."""
    ev = f.evidence or {}
    try:
        if scanner_type == "nmap":
            db.add(RawNmapFinding(
                import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
                host=ev.get("ip") or ev.get("hostname"),
                port=_safe_int(ev.get("port")),
                protocol=ev.get("protocol"),
                state=ev.get("state", "open"),
                service_name=ev.get("service"),
                service_product=ev.get("product"),
                service_version=ev.get("version"),
                os_name=ev.get("os"),
                cpe=ev.get("cpe"),
            ))
        elif scanner_type == "trivy":
            refs = ev.get("references", [])
            import json as _json
            db.add(RawTrivyFinding(
                import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
                target=f.resource_id,
                vulnerability_id=f.cve_id,
                package_name=ev.get("pkg"),
                installed_version=ev.get("installed"),
                fixed_version=ev.get("fixed"),
                primary_url=ev.get("primary_url"),
                references_json=_json.dumps(refs) if refs else None,
                severity=f.severity,
            ))
        elif scanner_type == "zap":
            instances = ev.get("instances") or []
            cwe_val = _safe_int(ev.get("cwe_id"))
            import json as _json
            db.add(RawZapFinding(
                import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
                alert_ref=f.control_id,
                alert_name=f.title,
                risk_desc=f.severity,
                url=instances[0] if instances else f.resource_id,
                reference=ev.get("reference"),
                cwe_id=cwe_val,
                description=f.description,
                solution=f.remediation,
                tags_json=_json.dumps(instances) if instances else None,
            ))
        elif scanner_type in ("gitleaks", "trufflehog", "secrets"):
            tool = "gitleaks" if scanner_type == "gitleaks" else "trufflehog"
            db.add(RawSecretFinding(
                import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
                tool=tool,
                rule_id=ev.get("rule") or ev.get("detector"),
                secret_type=ev.get("detector") or ev.get("rule") or f.title,
                file_path=ev.get("file"),
                line_number=_safe_int(ev.get("line")),
                commit_hash=ev.get("commit"),
                author=ev.get("author"),
                commit_date=_safe_dt(ev.get("date")),
                is_verified=ev.get("verified"),
            ))
        else:
            import json as _json
            db.add(RawGenericFinding(
                import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
                source_format=scanner_type,
                raw_row_json=_json.dumps({
                    "title": f.title, "severity": f.severity,
                    "resource_id": f.resource_id, "cve_id": f.cve_id,
                    "evidence": ev,
                }),
            ))
    except Exception as exc:
        logger.debug("Raw row insert failed for scanner %s finding %s: %s", scanner_type, finding_id, exc)


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
                "nvd_api_key",
            ):
                v = cfg.get(key) or creds.get(key)
                if v:
                    connector_fields[key] = v

    # Fall back to the platform-wide NVD API key (Key Vault-backed) when the
    # connector doesn't carry its own — so OWASP DC works without re-entering
    # the key per connector.
    if not connector_fields.get("nvd_api_key"):
        from core.config import get_settings
        platform_key = get_settings().NVD_API_KEY
        if platform_key:
            connector_fields["nvd_api_key"] = platform_key

    # Surface uploaded-binary metadata if any (CodeQL --mode=none mode).
    # Workflow uses these fields to decide whether to fetch the binary
    # from /scans/binary/{scan_id} instead of cloning a repo.
    binary_meta = (scan.summary or {}).get("binary") or {}

    return {
        "scan_id": scan_id,
        "target_url": runtime.get("target_url"),
        "profile": runtime.get("profile") or "baseline",
        "auth_headers": runtime.get("auth_headers") or {},
        "exclude_paths": runtime.get("exclude_paths") or [],
        # Workflow-scanner fields (private repo auth, target image, etc.)
        **connector_fields,
        # Binary-mode CodeQL scanning
        "binary_filename": binary_meta.get("filename") or None,
        "binary_size": binary_meta.get("size") or None,
        "binary_sha256": binary_meta.get("sha256") or None,
    }


# ── GET /scans/binary/{scan_id} ─────────────────────────────────────────────


@router.get("/scans/binary/{scan_id}")
async def fetch_scan_binary(
    scan_id: str,
    scan_token: str,
    db: Session = Depends(get_db),
):
    """Stream the uploaded binary back to the workflow runner. HMAC token
    gates access (same token the runner uses for /scans/config/)."""
    from fastapi.responses import FileResponse
    from services.scan_binaries import get_file_path, get_meta

    if verify_scan_token(scan_token, expected_scan_id=scan_id) is None:
        raise HTTPException(status_code=401, detail="Invalid or expired scan token")
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    path = get_file_path(scan_id)
    if not path:
        raise HTTPException(status_code=404, detail="No binary uploaded for this scan")
    meta = get_meta(scan_id) or {}
    return FileResponse(
        path=str(path),
        filename=meta.get("filename") or "binary.bin",
        media_type="application/octet-stream",
    )


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
async def ingest_scan_results(payload: IngestPayload = Body(...), db: Session = Depends(get_db), background_tasks: BackgroundTasks = None):  # type: ignore[assignment]
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

    # Determine scanner type + create AssessmentImport before findings loop
    scanner_type = _scanner_type_from_connector(db, scan)
    import_id = _create_ingest_import(db, scan, scanner_type, len(payload.findings))

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
            import_id=import_id,
        )
        db.add(finding)
        db.flush()  # get finding.id for raw row FK
        if import_id:
            _insert_ingest_raw_row(db, scanner_type, import_id, scan.client_id, f, finding.id)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    scan.summary = {**(scan.summary or {}), **sev_counts, "total": len(payload.findings)}
    scan.summary.pop("runtime", None)  # secrets — wipe after ingest
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()
    clear_runtime(payload.scan_id)

    # Recompute frameworks off the request path. Findings are already
    # committed above, so the scanner gets a fast 200 regardless of how long
    # the recompute takes. Running it inline (it iterates ~740 controls across
    # 3 frameworks) blocked the ingest POST past the scanner's client timeout
    # and piled memory pressure onto the request, risking an OOM kill that
    # made scans look like they ingested nothing.
    if background_tasks is not None:
        try:
            from services.compliance import recompute_all_frameworks_for_client_bg
            background_tasks.add_task(recompute_all_frameworks_for_client_bg, scan.client_id)
        except Exception:
            logger.exception("Failed to enqueue framework recompute for scan %s", scan.id)

    # Auto-generate the structured AI verdict on scan completion. Best-effort
    # background task — Verdict generator never raises out to the request,
    # and if no LLM provider is configured it falls back to deterministic text
    # so the UI always has something to render.
    if background_tasks is not None:
        try:
            from services.verdict import generate_verdict_bg
            background_tasks.add_task(generate_verdict_bg, scan.id)
        except Exception:
            logger.exception("Failed to enqueue verdict generation for scan %s", scan.id)

    # Phase 7B — fire buddy triggers for any new Critical / High findings.
    # We send one event per severity bucket (not per finding) with a sample
    # so the buddies get context without an explosion of LLM calls.
    if background_tasks is not None:
        try:
            from services.buddy_triggers import fire_event
            critical_findings = [f for f in payload.findings if (f.severity or "").lower() == "critical"]
            high_findings = [f for f in payload.findings if (f.severity or "").lower() == "high"]
            for kind, bucket in (("finding.critical", critical_findings), ("finding.high", high_findings)):
                if not bucket:
                    continue
                background_tasks.add_task(
                    fire_event,
                    event_kind=kind,
                    payload={
                        "_event_kind": kind,
                        "severity": kind.split(".")[1],
                        "count": len(bucket),
                        "scan_id": scan.id,
                        "client_id": scan.client_id,
                    },
                    client_id=scan.client_id,
                    scan_id=scan.id,
                    findings_for_prompt=[
                        {"title": f.title, "severity": (f.severity or "info").lower(),
                         "resource": f.resource_id, "cve": f.cve_id} for f in bucket[:8]
                    ],
                )
        except Exception:
            logger.exception("Failed to fire buddy triggers for scan %s", scan.id)

    return {"ok": True, "status": "completed", "ingested": len(payload.findings)}
