"""Global findings endpoints (across all scans for a client)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional, Dict, Any
from collections import defaultdict
from api.models.models import Finding, Scan, FrameworkType
from api.schemas.schemas import FindingResponse, FindingUpdate
from db.database import get_db
from core.security import get_current_user
from services.compliance import recompute_client_framework
from services.finding_classifier import classify, SECTIONS, CATEGORY_TO_SECTION

router = APIRouter(prefix="/clients/{client_id}/findings", tags=["findings"])


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    client_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    project_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    section: Optional[str] = None,
    category: Optional[str] = None,
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
    rows = q.order_by(desc(Finding.cvss_score), desc(Finding.created_at)).limit(2000).all()

    # Section/category filters happen in Python (heuristic-driven)
    if section or category:
        rows = [f for f in rows if (
            (not section or classify(f)[0] == section)
            and (not category or classify(f)[1] == category)
        )]

    # When filtering to a single scan, skip cross-scan deduplication — the
    # user wants to see every raw finding from that specific run.
    if scan_id:
        for f in rows:
            f.seen_count = 1
            f.first_seen_at = f.created_at
        rows.sort(key=lambda f: (f.cvss_score or 0, f.created_at or 0), reverse=True)
        return rows[:300]

    # Dedupe by (resource_id, title) — pick the latest detection as the
    # representative, set first_seen_at to the earliest, and seen_count to
    # the number of scans that flagged it. Same-issue duplicates from
    # multiple scans collapse to one row.
    def _key(f: Finding) -> tuple:
        return ((f.resource_id or "").strip().lower(), (f.title or "").strip().lower())

    grouped: Dict[tuple, List[Finding]] = defaultdict(list)
    for f in rows:
        grouped[_key(f)].append(f)

    deduped: List[Finding] = []
    for group in grouped.values():
        # Latest first by created_at (already sorted from query)
        latest = max(group, key=lambda x: x.created_at or 0)
        earliest = min(
            (g for g in group if g.created_at is not None),
            key=lambda x: x.created_at,
            default=latest,
        )
        # Set extra attrs that FindingResponse picks up via from_attributes
        latest.seen_count = len(group)
        latest.first_seen_at = earliest.created_at
        deduped.append(latest)

    deduped.sort(key=lambda f: (f.cvss_score or 0, f.created_at or 0), reverse=True)
    return deduped[:300]


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


@router.patch("/{finding_id}", response_model=FindingResponse)
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


@router.delete("/{finding_id}")
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


@router.post("/cleanup-blank")
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
