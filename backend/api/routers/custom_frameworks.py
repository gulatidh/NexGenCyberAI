"""Custom framework endpoints — create, manage, and pick controls for user-defined compliance frameworks."""
import logging
import re
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.models.models import CustomFramework, CustomFrameworkControl, FrameworkControl
from db.database import get_db
from core.security import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["custom_frameworks"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class CustomFrameworkCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class CustomFrameworkControlItem(BaseModel):
    id: str
    framework: str
    control_id: str
    domain: Optional[str]
    title: str
    description: Optional[str]
    weight: int

    class Config:
        from_attributes = True


class CustomFrameworkDetail(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str]
    created_by: Optional[str]
    controls: List[CustomFrameworkControlItem]

    class Config:
        from_attributes = True


class CustomFrameworkSummary(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str]
    control_count: int

    class Config:
        from_attributes = True


class AddControlsRequest(BaseModel):
    control_ids: List[str] = Field(..., description="List of FrameworkControl.id values to add")


class FrameworkControlPickerItem(BaseModel):
    id: str
    framework: str
    control_id: str
    domain: Optional[str]
    title: str
    description: Optional[str]
    weight: int

    class Config:
        from_attributes = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_slug(name: str) -> str:
    """Convert a display name to a URL-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "framework"


def _unique_slug(db: Session, base: str, exclude_id: Optional[str] = None) -> str:
    """Return base slug, appending -2/-3/… until it is unique."""
    candidate = base
    counter = 2
    while True:
        q = db.query(CustomFramework).filter(CustomFramework.slug == candidate)
        if exclude_id:
            q = q.filter(CustomFramework.id != exclude_id)
        if not q.first():
            return candidate
        candidate = f"{base}-{counter}"
        counter += 1


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/frameworks/custom/", response_model=List[CustomFrameworkSummary])
async def list_custom_frameworks(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List all custom frameworks with control counts."""
    frameworks = db.query(CustomFramework).order_by(CustomFramework.name.asc()).all()
    result = []
    for fw in frameworks:
        result.append(CustomFrameworkSummary(
            id=fw.id,
            name=fw.name,
            slug=fw.slug,
            description=fw.description,
            control_count=len(fw.controls),
        ))
    return result


@router.post("/frameworks/custom/", response_model=CustomFrameworkSummary, status_code=201)
async def create_custom_framework(
    payload: CustomFrameworkCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Create a new custom framework. Slug is auto-generated from name."""
    base_slug = _make_slug(payload.name)
    slug = _unique_slug(db, base_slug)
    fw = CustomFramework(
        name=payload.name,
        slug=slug,
        description=payload.description,
        created_by=user.get("email") if isinstance(user, dict) else getattr(user, "email", None),
    )
    db.add(fw)
    db.commit()
    db.refresh(fw)
    return CustomFrameworkSummary(
        id=fw.id,
        name=fw.name,
        slug=fw.slug,
        description=fw.description,
        control_count=0,
    )


@router.get("/frameworks/custom/{cf_id}/", response_model=CustomFrameworkDetail)
async def get_custom_framework(
    cf_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get a custom framework with its full control list."""
    fw = db.query(CustomFramework).filter(CustomFramework.id == cf_id).first()
    if not fw:
        raise HTTPException(status_code=404, detail="Custom framework not found")

    controls = []
    for link in fw.controls:
        fc = link.framework_control
        if fc:
            fw_val = fc.framework.value if hasattr(fc.framework, "value") else str(fc.framework)
            controls.append(CustomFrameworkControlItem(
                id=fc.id,
                framework=fw_val,
                control_id=fc.control_id,
                domain=fc.domain,
                title=fc.title,
                description=fc.description,
                weight=fc.weight if fc.weight is not None else 1,
            ))

    return CustomFrameworkDetail(
        id=fw.id,
        name=fw.name,
        slug=fw.slug,
        description=fw.description,
        created_by=fw.created_by,
        controls=controls,
    )


@router.delete("/frameworks/custom/{cf_id}/", status_code=204)
async def delete_custom_framework(
    cf_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Delete a custom framework and all its control links (cascade via ORM)."""
    fw = db.query(CustomFramework).filter(CustomFramework.id == cf_id).first()
    if not fw:
        raise HTTPException(status_code=404, detail="Custom framework not found")
    db.delete(fw)
    db.commit()


@router.post("/frameworks/custom/{cf_id}/controls/", status_code=201)
async def add_controls_to_custom_framework(
    cf_id: str,
    payload: AddControlsRequest,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Add one or more FrameworkControl rows to a custom framework by their UUIDs."""
    fw = db.query(CustomFramework).filter(CustomFramework.id == cf_id).first()
    if not fw:
        raise HTTPException(status_code=404, detail="Custom framework not found")

    existing_fk_ids = {link.framework_control_id for link in fw.controls}
    added = 0
    not_found = []

    for fk_ctrl_id in payload.control_ids:
        if fk_ctrl_id in existing_fk_ids:
            continue  # already linked
        fc = db.query(FrameworkControl).filter(FrameworkControl.id == fk_ctrl_id).first()
        if not fc:
            not_found.append(fk_ctrl_id)
            continue
        link = CustomFrameworkControl(
            custom_framework_id=cf_id,
            framework_control_id=fk_ctrl_id,
        )
        db.add(link)
        existing_fk_ids.add(fk_ctrl_id)
        added += 1

    db.commit()
    return {"added": added, "not_found": not_found}


@router.delete("/frameworks/custom/{cf_id}/controls/{fk_ctrl_id}/", status_code=204)
async def remove_control_from_custom_framework(
    cf_id: str,
    fk_ctrl_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Remove a single control link from a custom framework."""
    fw = db.query(CustomFramework).filter(CustomFramework.id == cf_id).first()
    if not fw:
        raise HTTPException(status_code=404, detail="Custom framework not found")

    link = (
        db.query(CustomFrameworkControl)
        .filter(
            CustomFrameworkControl.custom_framework_id == cf_id,
            CustomFrameworkControl.framework_control_id == fk_ctrl_id,
        )
        .first()
    )
    if not link:
        raise HTTPException(status_code=404, detail="Control not found in this custom framework")
    db.delete(link)
    db.commit()


@router.get("/frameworks/controls/", response_model=List[FrameworkControlPickerItem])
async def list_framework_controls_picker(
    framework: Optional[str] = Query(None, description="Filter by framework slug, e.g. nist_csf"),
    domain: Optional[str] = Query(None, description="Filter by domain (case-insensitive substring)"),
    search: Optional[str] = Query(None, description="Search term matched against control_id, title, description"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List FrameworkControl rows for the picker UI. Paginated 100 at a time.

    Supports optional filters: framework slug, domain substring, and free-text search
    across control_id, title, and description.
    """
    PAGE_SIZE = 100

    q = db.query(FrameworkControl)

    if framework:
        # Match by the string value of the enum column
        q = q.filter(FrameworkControl.framework == framework)

    if domain:
        q = q.filter(FrameworkControl.domain.ilike(f"%{domain}%"))

    if search:
        term = f"%{search}%"
        q = q.filter(
            FrameworkControl.control_id.ilike(term)
            | FrameworkControl.title.ilike(term)
            | FrameworkControl.description.ilike(term)
        )

    offset = (page - 1) * PAGE_SIZE
    rows = (
        q.order_by(FrameworkControl.framework.asc(), FrameworkControl.control_id.asc())
        .offset(offset)
        .limit(PAGE_SIZE)
        .all()
    )

    result = []
    for fc in rows:
        fw_val = fc.framework.value if hasattr(fc.framework, "value") else str(fc.framework)
        result.append(FrameworkControlPickerItem(
            id=fc.id,
            framework=fw_val,
            control_id=fc.control_id,
            domain=fc.domain,
            title=fc.title,
            description=fc.description,
            weight=fc.weight if fc.weight is not None else 1,
        ))
    return result
