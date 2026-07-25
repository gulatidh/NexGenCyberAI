"""Global findings endpoints (across all scans for a client)."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional, Dict, Any
from collections import defaultdict
import csv
import io
from pydantic import BaseModel
from api.models.models import Finding, Scan, FrameworkType
from api.schemas.schemas import FindingResponse, FindingUpdate
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere
from services.compliance import recompute_client_framework
from services.finding_classifier import classify, SECTIONS, CATEGORY_TO_SECTION

router = APIRouter(prefix="/clients/{client_id}/findings", tags=["findings"])


class SuppressPayload(BaseModel):
    reason: str = ""


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    client_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    project_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    section: Optional[str] = None,
    category: Optional[str] = None,
    include_suppressed: bool = False,
    limit: int = 300,
    offset: int = 0,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id)
    )
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if project_id:
        q = q.filter(Scan.project_id == project_id)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    else:
        # Global view: only show findings from the live version of each scan chain.
        # When is_live column doesn't exist yet (pre-migration), default to all scans.
        try:
            q = q.filter(Scan.is_live == True)  # noqa: E712
        except Exception:
            pass
    # Filter out suppressed (false positive) findings by default.
    if not include_suppressed:
        q = q.filter(Finding.suppressed_at.is_(None))
    # For the global (cross-scan) view, filter to canonical findings only.
    # Duplicate marker rows (duplicate_of_id IS NOT NULL) represent re-detections
    # of an already-known issue; they are counted on the canonical row via
    # occurrence_count and should not appear as separate entries.
    if not scan_id:
        q = q.filter(Finding.duplicate_of_id.is_(None))

    rows = q.order_by(desc(Finding.cvss_score), desc(Finding.created_at)).offset(offset).limit(min(limit, 5000)).all()

    # Section/category filters happen in Python (heuristic-driven)
    if section or category:
        rows = [f for f in rows if (
            (not section or classify(f)[0] == section)
            and (not category or classify(f)[1] == category)
        )]

    # When filtering to a single scan, skip cross-scan deduplication — the
    # user wants to see every raw finding from that specific run (including
    # duplicate markers so per-scan counts match the scan summary).
    if scan_id:
        for f in rows:
            f.seen_count = getattr(f, "occurrence_count", None) or 1
            f.first_seen_at = f.created_at
        rows.sort(key=lambda f: (f.cvss_score or 0, f.created_at or 0), reverse=True)
        return rows[:min(limit, 5000)]

    # Global view: rows are already canonical-only (duplicate_of_id IS NULL).
    # Dedupe by (resource_id, title) to collapse any pre-dedup-era duplicates
    # (old data written before this feature was deployed), and set seen_count
    # from occurrence_count where available, otherwise count the group size.
    def _key(f: Finding) -> tuple:
        return ((f.resource_id or "").strip().lower(), (f.title or "").strip().lower())

    grouped: Dict[tuple, List[Finding]] = defaultdict(list)
    for f in rows:
        grouped[_key(f)].append(f)

    deduped: List[Finding] = []
    for group in grouped.values():
        latest = max(group, key=lambda x: x.created_at or 0)
        earliest = min(
            (g for g in group if g.created_at is not None),
            key=lambda x: x.created_at,
            default=latest,
        )
        # Prefer occurrence_count from DB (write-side dedup); fall back to
        # the Python group size (read-side dedup for pre-existing data).
        db_occ = getattr(latest, "occurrence_count", None)
        latest.seen_count = max(len(group), db_occ or 1)
        latest.first_seen_at = earliest.created_at
        # last_seen_at comes straight from the model attribute (may be None for old rows)
        deduped.append(latest)

    deduped.sort(key=lambda f: (f.cvss_score or 0, f.created_at or 0), reverse=True)
    return deduped[:min(limit, 5000)]


@router.get("/categories")
async def get_finding_categories(
    client_id: str,
    project_id: Optional[str] = None,
    status: Optional[str] = "open",
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> Dict[str, Any]:
    """Return finding counts grouped by (section, category). Powers the
    sub-navigation on the Findings page."""
    q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id)
    )
    if status:
        q = q.filter(Finding.status == status)
    if project_id:
        q = q.filter(Scan.project_id == project_id)
    try:
        q = q.filter(Scan.is_live == True)  # noqa: E712
    except Exception:
        pass

    counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in q.all():
        s, c = classify(f)
        counts[s][c] += 1

    sections_out = []
    for section_key, cats in SECTIONS.items():
        category_rows = []
        section_total = 0
        for cat_key, label, icon in cats:
            n = counts[section_key].get(cat_key, 0)
            section_total += n
            category_rows.append({"key": cat_key, "label": label, "icon": icon, "count": n})
        sections_out.append({
            "key": section_key,
            "label": section_key.replace("_", " ").title(),
            "total": section_total,
            "categories": category_rows,
        })
    return {"sections": sections_out, "grand_total": sum(s["total"] for s in sections_out)}


@router.get("/export/")
async def export_findings_csv(
    client_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id)
    )
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    else:
        try:
            q = q.filter(Scan.is_live == True)  # noqa: E712
        except Exception:
            pass
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    rows = q.order_by(desc(Finding.cvss_score), desc(Finding.created_at)).limit(10000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "title", "severity", "status", "resource_id", "resource_type", "cve_id", "cvss_score", "control_id", "framework", "description", "remediation", "created_at"])
    for f in rows:
        writer.writerow([
            f.id, f.title,
            f.severity.value if hasattr(f.severity, "value") else f.severity,
            f.status.value if hasattr(f.status, "value") else f.status,
            f.resource_id or "", f.resource_type or "", f.cve_id or "",
            f.cvss_score or "", f.control_id or "",
            f.framework.value if hasattr(f.framework, "value") else (f.framework or ""),
            (f.description or "").replace("\n", " "), (f.remediation or "").replace("\n", " "),
            f.created_at.isoformat() if f.created_at else "",
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings-{client_id}.csv"},
    )


@router.patch("/{finding_id}", response_model=FindingResponse, dependencies=[Depends(require_editor_anywhere)])
async def update_finding_status(
    client_id: str,
    finding_id: str,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    f = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Finding.id == finding_id, Scan.client_id == client_id)
        .first()
    )
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(f, k, v)
    db.commit()
    db.refresh(f)
    if f.framework:
        try:
            fv = f.framework.value if hasattr(f.framework, "value") else str(f.framework)
            recompute_client_framework(db, client_id, FrameworkType(fv))
        except Exception:
            pass
    return f


@router.post("/{finding_id}/suppress", response_model=FindingResponse, dependencies=[Depends(require_editor_anywhere)])
async def suppress_finding(
    client_id: str,
    finding_id: str,
    payload: SuppressPayload,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Mark a finding as a false positive / suppressed."""
    from datetime import datetime, timezone
    f = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Finding.id == finding_id, Scan.client_id == client_id)
        .first()
    )
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.suppressed_at = datetime.now(timezone.utc)
    f.suppression_reason = payload.reason
    f.status = "false_positive"
    db.commit()
    db.refresh(f)
    return f


@router.delete("/{finding_id}/suppress", response_model=FindingResponse, dependencies=[Depends(require_editor_anywhere)])
async def unsuppress_finding(
    client_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Remove a false-positive suppression and reopen the finding."""
    f = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Finding.id == finding_id, Scan.client_id == client_id)
        .first()
    )
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.suppressed_at = None
    f.suppression_reason = None
    f.status = "open"
    db.commit()
    db.refresh(f)
    return f


@router.post("/{finding_id}/playbook", response_model=FindingResponse, dependencies=[Depends(require_editor_anywhere)])
async def generate_playbook(
    client_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Generate a step-by-step remediation runbook for this finding using LLM."""
    f = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Finding.id == finding_id, Scan.client_id == client_id)
        .first()
    )
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    from core.ai_providers import get_llm, ProviderUnavailableError
    from langchain_core.messages import HumanMessage, SystemMessage

    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    prompt = f"""You are a senior security engineer. Generate a detailed, actionable remediation runbook for the following security finding.

Finding: {f.title}
Severity: {sev}
Resource: {f.resource_id or "N/A"} ({f.resource_type or "N/A"})
CVE: {f.cve_id or "N/A"} | CVSS: {f.cvss_score or "N/A"}
Description: {f.description or "N/A"}
Current remediation note: {f.remediation or "N/A"}

Write a playbook with these sections:
## Summary
One paragraph explaining the risk and business impact.

## Prerequisites
Bullet list of what you need before starting (tools, access, backups).

## Step-by-Step Fix
Numbered steps with exact commands where applicable.

## Verification
How to confirm the fix worked (tests, commands, checks).

## Rollback
Steps to undo the fix if something breaks.

## References
Links or standards (CVE, CWE, OWASP, framework control IDs).

Be specific and technical. Include real commands where possible."""

    try:
        llm = get_llm()
        response = await llm.ainvoke([
            SystemMessage(content="You are a senior security engineer generating remediation playbooks."),
            HumanMessage(content=prompt),
        ])
        playbook_text = response.content if hasattr(response, "content") else str(response)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"LLM unavailable: {exc}")

    f.playbook = playbook_text
    db.commit()
    db.refresh(f)
    return f


@router.delete("/{finding_id}", dependencies=[Depends(require_editor_anywhere)])
async def delete_finding(
    client_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    f = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Finding.id == finding_id, Scan.client_id == client_id)
        .first()
    )
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(f)
    db.commit()
    return {"deleted": True}


@router.post("/cleanup-blank", dependencies=[Depends(require_editor_anywhere)])
async def delete_blank_findings(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Delete findings that have no meaningful content (empty/whitespace title
    AND no description AND no resource_id). Useful for tidying up after a
    scanner that returned partial rows."""
    q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id)
    )
    blanks = [
        f for f in q.all()
        if not (f.title or "").strip()
        and not (f.description or "").strip()
        and not (f.resource_id or "").strip()
    ]
    for f in blanks:
        db.delete(f)
    db.commit()
    return {"deleted": len(blanks)}
