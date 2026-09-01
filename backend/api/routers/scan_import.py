"""
Scan Import router — upload offline scan result files.

Endpoints:
  POST /clients/{client_id}/scans/import/parse        — parse & preview (no DB write)
  POST /clients/{client_id}/scans/import/commit       — save to DB + raw tables
  GET  /clients/{client_id}/scans/import/history      — list import sessions
  GET  /clients/{client_id}/scans/import/imports      — same, cleaner path
  GET  /clients/{client_id}/scans/import/raw/{scanner_type} — raw rows for a scanner
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.models.models import (
    AssessmentImport, ConnectorType, Finding, RawBurpFinding, RawGenericFinding,
    RawNessusFinding, RawOpenVASFinding, RawQualysFinding, RawSarifFinding,
    RawTenableFinding, Scan, ScanStatus, ScanType,
)
from core.authz import require_editor_anywhere
from core.security import get_current_user
from db.database import get_db
from services.scan_importer import compute_delta, import_scan_file

router = APIRouter(
    prefix="/clients/{client_id}/scans/import",
    tags=["scan-import"],
)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


# ── helpers ────────────────────────────────────────────────────────────────────

def _safe_float(v) -> Optional[float]:
    try:
        return float(v) if v is not None else None
    except (ValueError, TypeError):
        return None


def _safe_int(v) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except (ValueError, TypeError):
        return None


def _safe_dt(v) -> Optional[datetime]:
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    try:
        from dateutil import parser as dtparser
        return dtparser.parse(str(v))
    except Exception:
        return None


def _generate_import_ref(db: Session, client_id: str) -> str:
    year = datetime.utcnow().year
    count = db.query(func.count(AssessmentImport.id)).filter(
        AssessmentImport.client_id == client_id,
        func.extract("year", AssessmentImport.created_at) == year,
    ).scalar() or 0
    return f"IMP-{year}-{count + 1:03d}"


def _format_to_scanner_type(fmt: str, tool_hint: str = "") -> str:
    """Map detected format + tool hint to a canonical scanner_type string."""
    hint = (tool_hint or "").lower()
    if "tenable" in hint:
        return "tenable"
    fmt_map = {
        "nessus": "nessus",
        "burp": "burp",
        "qualys_xml": "qualys",
        "qualys_csv": "qualys",
        "openvas": "openvas",
        "sarif": "sarif",
        "checkmarx": "generic",
        "csv": "generic",
        "json": "generic",
        "pdf": "generic",
        "text": "generic",
        "unknown": "generic",
        "xml_unknown": "generic",
    }
    return fmt_map.get(fmt, "generic")


# ── raw row inserters ──────────────────────────────────────────────────────────

def _insert_raw_tenable(db, import_id: int, client_id: str, raw: Dict, finding_id: Optional[int]) -> None:
    row = RawTenableFinding(
        import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
        plugin_id=str(raw.get("plugin_id", "")),
        plugin_name=raw.get("plugin_name"),
        plugin_family=raw.get("plugin_family"),
        risk_factor=raw.get("risk_factor"),
        vpr_score=_safe_float(raw.get("vpr_score")),
        asset_uuid=raw.get("asset_uuid"),
        asset_hostname=raw.get("host"),
        asset_ip=raw.get("host"),
        asset_criticality_rating=raw.get("asset_criticality_rating"),
        first_seen=_safe_dt(raw.get("first_seen")),
        last_seen=_safe_dt(raw.get("last_seen")),
        tenable_scan_id=str(raw.get("tenable_scan_id")) if raw.get("tenable_scan_id") else None,
        synopsis=raw.get("synopsis"),
        description=raw.get("description"),
        solution=raw.get("solution"),
        see_also=raw.get("see_also"),
        plugin_output=raw.get("plugin_output"),
        port=_safe_int(raw.get("port")),
        protocol=raw.get("protocol"),
        cve=raw.get("cve"),
        cvss_v3_base_score=_safe_float(raw.get("cvss3_base_score")),
        cvss_v3_temporal_score=_safe_float(raw.get("cvss3_temporal_score")),
        cvss_v3_vector=raw.get("cvss3_vector"),
        patch_available=raw.get("patch_available"),
        exploit_available=raw.get("exploit_available"),
        exploit_ease=raw.get("exploitability_ease"),
        metasploit=raw.get("metasploit"),
    )
    db.add(row)


def _insert_raw_nessus(db, import_id: int, client_id: str, raw: Dict, finding_id: Optional[int]) -> None:
    row = RawNessusFinding(
        import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
        plugin_id=str(raw.get("plugin_id", "")),
        plugin_name=raw.get("plugin_name"),
        plugin_family=raw.get("plugin_family"),
        severity_id=_safe_int(raw.get("severity_id")),
        risk_factor=raw.get("risk_factor"),
        description=raw.get("description"),
        solution=raw.get("solution"),
        synopsis=raw.get("synopsis"),
        plugin_output=raw.get("plugin_output"),
        host=raw.get("host"),
        port=_safe_int(raw.get("port")),
        protocol=raw.get("protocol"),
        cvss_base_score=_safe_float(raw.get("cvss_base_score")),
        cvss_temporal_score=_safe_float(raw.get("cvss_temporal_score")),
        cvss_vector=raw.get("cvss_vector"),
        cvss3_base_score=_safe_float(raw.get("cvss3_base_score")),
        cvss3_temporal_score=_safe_float(raw.get("cvss3_temporal_score")),
        cvss3_vector=raw.get("cvss3_vector"),
        cve=raw.get("cve"),
        bid=raw.get("bid"),
        see_also=raw.get("see_also"),
        exploit_available=raw.get("exploit_available"),
        exploitability_ease=raw.get("exploitability_ease"),
        metasploit=raw.get("metasploit"),
        patch_available=raw.get("patch_available"),
    )
    db.add(row)


def _insert_raw_burp(db, import_id: int, client_id: str, raw: Dict, finding_id: Optional[int]) -> None:
    row = RawBurpFinding(
        import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
        issue_type_id=raw.get("issue_type_id"),
        issue_name=raw.get("issue_name"),
        issue_detail=raw.get("issue_detail"),
        issue_background=raw.get("issue_background"),
        remediation_detail=raw.get("remediation_detail"),
        remediation_background=raw.get("remediation_background"),
        path=raw.get("path"),
        host=raw.get("host"),
        port=_safe_int(raw.get("port")),
        protocol=raw.get("protocol"),
        confidence=raw.get("confidence"),
        severity=raw.get("severity"),
        vulnerability_classifications=raw.get("vulnerability_classifications"),
        references=raw.get("references"),
        cwes=raw.get("cwes"),
        request_response=(raw.get("request_response") or "")[:10000],
    )
    db.add(row)


def _insert_raw_qualys(db, import_id: int, client_id: str, raw: Dict, finding_id: Optional[int]) -> None:
    row = RawQualysFinding(
        import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
        qid=raw.get("qid"),
        title=raw.get("title"),
        type_code=raw.get("type_code"),
        severity_level=_safe_int(raw.get("severity_level")),
        port=_safe_int(raw.get("port")),
        protocol=raw.get("protocol"),
        fqdn=raw.get("fqdn"),
        ip=raw.get("ip"),
        os=raw.get("os"),
        results=raw.get("results"),
        threat=raw.get("threat"),
        impact=raw.get("impact"),
        solution=raw.get("solution"),
        cvss_base=_safe_float(raw.get("cvss_base")),
        cvss_temporal=_safe_float(raw.get("cvss_temporal")),
        cvss3_base=_safe_float(raw.get("cvss3_base")),
        cvss3_temporal=_safe_float(raw.get("cvss3_temporal")),
        cve_list=raw.get("cve_list"),
        vendor_reference=raw.get("vendor_reference"),
        category=raw.get("category"),
        is_patchable=raw.get("is_patchable"),
        first_found=_safe_dt(raw.get("first_found")),
        last_found=_safe_dt(raw.get("last_found")),
    )
    db.add(row)


def _insert_raw_openvas(db, import_id: int, client_id: str, raw: Dict, finding_id: Optional[int]) -> None:
    row = RawOpenVASFinding(
        import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
        nvt_oid=raw.get("nvt_oid"),
        nvt_name=raw.get("nvt_name"),
        nvt_family=raw.get("nvt_family"),
        nvt_version=raw.get("nvt_version"),
        host=raw.get("host"),
        port=raw.get("port"),
        threat=raw.get("threat"),
        severity_score=_safe_float(raw.get("severity_score")),
        qod=_safe_int(raw.get("qod")),
        description=raw.get("description"),
        solution=raw.get("solution"),
        solution_type=raw.get("solution_type"),
        cve=raw.get("cve"),
        bid=raw.get("bid"),
        xref=raw.get("xref"),
        tags=raw.get("tags"),
    )
    db.add(row)


def _insert_raw_sarif(db, import_id: int, client_id: str, raw: Dict, finding_id: Optional[int]) -> None:
    row = RawSarifFinding(
        import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
        tool_name=raw.get("tool_name"),
        tool_version=raw.get("tool_version"),
        rule_id=raw.get("rule_id"),
        rule_name=raw.get("rule_name"),
        level=raw.get("level"),
        message=raw.get("message"),
        artifact_uri=raw.get("artifact_uri"),
        region_start_line=_safe_int(raw.get("region_start_line")),
        region_end_line=_safe_int(raw.get("region_end_line")),
        region_start_column=_safe_int(raw.get("region_start_column")),
        logical_location=raw.get("logical_location"),
        fingerprint=raw.get("fingerprint"),
        suppressed=bool(raw.get("suppressed", False)),
        rank=_safe_float(raw.get("rank")),
        tags=raw.get("tags"),
        properties_json=raw.get("properties_json"),
    )
    db.add(row)


def _insert_raw_generic(db, import_id: int, client_id: str, raw: Dict, finding_id: Optional[int], row_num: int, fmt: str) -> None:
    row = RawGenericFinding(
        import_id=import_id, client_id=client_id, normalized_finding_id=finding_id,
        source_format=raw.get("source_format") or fmt,
        row_number=row_num,
        raw_row_json=raw.get("raw_row_json") or json.dumps(raw),
    )
    db.add(row)


_RAW_INSERTERS = {
    "tenable": _insert_raw_tenable,
    "nessus": _insert_raw_nessus,
    "burp": _insert_raw_burp,
    "qualys": _insert_raw_qualys,
    "openvas": _insert_raw_openvas,
    "sarif": _insert_raw_sarif,
}


def _insert_raw(db, scanner_type: str, import_id: int, client_id: str, raw: Dict, finding_id: Optional[int], row_num: int, fmt: str) -> None:
    """Route to the correct raw inserter based on scanner_type or raw["_table"]."""
    table_hint = raw.get("_table", "")
    effective = table_hint if table_hint else scanner_type
    inserter = _RAW_INSERTERS.get(effective)
    if inserter:
        inserter(db, import_id, client_id, raw, finding_id)
    else:
        _insert_raw_generic(db, import_id, client_id, raw, finding_id, row_num, fmt)


# ── endpoints ─────────────────────────────────────────────────────────────────

@router.post("/parse")
async def parse_scan_file(
    client_id: str,
    file: UploadFile = File(...),
    tool_hint: str = Form(default=""),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Parse an uploaded scan file and return a preview — no DB write."""
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 50 MB)")
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    from core.config import get_settings
    settings = get_settings()

    fmt, findings = await import_scan_file(
        content,
        filename=file.filename or "upload",
        tool_hint=tool_hint,
        nvd_api_key=settings.NVD_API_KEY,
    )

    existing = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.status == "open",
            Finding.suppressed_at.is_(None),
        )
        .all()
    )
    delta = compute_delta(findings, existing)

    sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    avg_conf_pct = (
        round(sum(f.confidence for f in findings) / len(findings) * 100) if findings else 0
    )

    scanner_type = _format_to_scanner_type(fmt, tool_hint)
    year = datetime.utcnow().year

    return {
        "detected_format": fmt,
        "scanner_type": scanner_type,
        "import_ref_preview": f"IMP-{year}-NNN",
        "finding_count": len(findings),
        "severity_breakdown": sev_counts,
        "avg_confidence": avg_conf_pct,
        "new_count": delta.new_count,
        "fixed_count": delta.fixed_count,
        "persisting_count": delta.persisting_count,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "resource": f.resource_id,
                "cve_id": f.cve_id,
                "confidence": round(f.confidence * 100),
            }
            for f in findings
        ],
    }


@router.post("/commit", status_code=201)
async def commit_scan_import(
    client_id: str,
    file: UploadFile = File(...),
    tool_hint: str = Form(default=""),
    scan_name: str = Form(default=""),
    import_name: str = Form(default=""),
    project_id: Optional[str] = Form(default=None),
    db: Session = Depends(get_db),
    user=Depends(require_editor_anywhere),
):
    """Parse a scan file and save findings + raw scanner rows to the database."""
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 50 MB)")
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    from core.config import get_settings
    settings = get_settings()

    fmt, findings = await import_scan_file(
        content,
        filename=file.filename or "upload",
        tool_hint=tool_hint,
        nvd_api_key=settings.NVD_API_KEY,
    )

    if not findings:
        raise HTTPException(status_code=422, detail="No findings could be extracted from the file")

    initiator = (
        user.get("preferred_username")
        or user.get("upn")
        or user.get("email")
        or user.get("sub")
        or "unknown"
    )

    # Resolve final import name
    final_name = import_name.strip() or scan_name.strip() or f"{fmt} import – {datetime.utcnow().strftime('%Y-%m-%d')}"
    scanner_type = _format_to_scanner_type(fmt, tool_hint)
    import_ref = _generate_import_ref(db, client_id)

    # Create AssessmentImport record
    ai_record = AssessmentImport(
        client_id=client_id,
        project_id=project_id or None,
        import_name=final_name,
        import_ref=import_ref,
        scanner_type=scanner_type,
        detected_format=fmt,
        source_filename=file.filename,
        raw_finding_count=len(findings),
        normalized_finding_count=0,
        created_by=initiator,
        status="processing",
    )
    db.add(ai_record)
    db.flush()

    # Create Scan record
    raw_ctx = json.dumps({
        "source_format": fmt,
        "filename": file.filename,
        "tool_hint": tool_hint,
        "import": True,
        "import_id": ai_record.id,
        "import_ref": import_ref,
    })
    scan = Scan(
        id=str(uuid.uuid4()),
        client_id=client_id,
        project_id=project_id or None,
        connector_type=ConnectorType.UPLOAD,
        scan_type=ScanType.VULNERABILITY,
        status=ScanStatus.COMPLETED,
        target=file.filename or "uploaded_file",
        name=final_name,
        initiated_by=initiator,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        raw_context=raw_ctx,
        progress_message=f"Imported {len(findings)} findings from {fmt} format",
    )
    db.add(scan)
    db.flush()

    # Update import record with scan_id
    ai_record.scan_id = scan.id

    # Insert findings + raw rows
    normalized_count = 0
    for idx, pf in enumerate(findings):
        kwargs = pf.to_finding_kwargs(scan.id, fmt)
        kwargs["import_id"] = ai_record.id
        finding_obj = Finding(**kwargs)
        db.add(finding_obj)
        db.flush()  # get finding_obj.id

        _insert_raw(db, scanner_type, ai_record.id, client_id, pf.raw, finding_obj.id, idx, fmt)
        normalized_count += 1

    ai_record.normalized_finding_count = normalized_count
    ai_record.status = "completed"

    # Compute delta
    existing = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.status == "open",
            Finding.scan_id != scan.id,
            Finding.suppressed_at.is_(None),
        )
        .all()
    )
    delta = compute_delta(findings, existing)

    db.commit()

    return {
        "scan_id": scan.id,
        "import_id": ai_record.id,
        "import_ref": import_ref,
        "import_name": final_name,
        "format": fmt,
        "scanner_type": scanner_type,
        "findings_imported": normalized_count,
        "raw_rows_stored": normalized_count,
        "delta": {
            "new": delta.new_count,
            "fixed": delta.fixed_count,
            "persisting": delta.persisting_count,
        },
    }


@router.get("/history")
@router.get("/imports")
def import_history(
    client_id: str,
    limit: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List previous assessment imports for this client."""
    rows = (
        db.query(AssessmentImport)
        .filter(AssessmentImport.client_id == client_id)
        .order_by(AssessmentImport.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "import_name": r.import_name,
            "import_ref": r.import_ref,
            "scanner_type": r.scanner_type,
            "detected_format": r.detected_format,
            "raw_finding_count": r.raw_finding_count,
            "normalized_finding_count": r.normalized_finding_count,
            "source_filename": r.source_filename,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "created_by": r.created_by,
            "scan_id": r.scan_id,
            "status": r.status,
            # legacy compat fields
            "scan_name": r.import_name,
            "finding_count": r.normalized_finding_count,
        }
        for r in rows
    ]


_RAW_TABLE_MAP = {
    "tenable": RawTenableFinding,
    "nessus": RawNessusFinding,
    "burp": RawBurpFinding,
    "qualys": RawQualysFinding,
    "openvas": RawOpenVASFinding,
    "sarif": RawSarifFinding,
    "generic": RawGenericFinding,
}


@router.get("/raw/{scanner_type}")
def get_raw_findings(
    client_id: str,
    scanner_type: str,
    import_id: Optional[int] = Query(default=None),
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return raw scanner-native rows for a given scanner type and optional import."""
    model = _RAW_TABLE_MAP.get(scanner_type)
    if not model:
        raise HTTPException(status_code=400, detail=f"Unknown scanner_type '{scanner_type}'. Valid: {list(_RAW_TABLE_MAP)}")

    q = db.query(model).filter(model.client_id == client_id)
    if import_id is not None:
        q = q.filter(model.import_id == import_id)
    rows = q.limit(limit).all()

    result = []
    for r in rows:
        d = {c.name: getattr(r, c.name) for c in r.__table__.columns}
        result.append(d)
    return result
