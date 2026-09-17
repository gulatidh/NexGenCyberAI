"""System Knowledge Base — Owlet technical reference entries (admin-editable, assistant-injectable)."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.models.models import SystemKBEntry
from db.database import get_db
from core.security import get_current_user, require_admin

router = APIRouter(prefix="/system-kb", tags=["system-kb"])


class KBEntryOut(BaseModel):
    section_key: str
    section_title: str
    icon_name: Optional[str] = None
    content: str
    version: int
    last_updated_by: Optional[str] = None
    last_updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class KBEntryUpdate(BaseModel):
    content: str
    section_title: Optional[str] = None


@router.get("/", response_model=list[KBEntryOut])
async def list_entries(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(SystemKBEntry).order_by(SystemKBEntry.section_key).all()


@router.get("/{section_key}", response_model=KBEntryOut)
async def get_entry(section_key: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    entry = db.query(SystemKBEntry).filter(SystemKBEntry.section_key == section_key).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Section not found")
    return entry


@router.patch("/{section_key}", response_model=KBEntryOut)
async def update_entry(
    section_key: str,
    body: KBEntryUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Update a KB section. Admin only."""
    entry = db.query(SystemKBEntry).filter(SystemKBEntry.section_key == section_key).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Section not found")
    entry.content = body.content
    if body.section_title:
        entry.section_title = body.section_title
    entry.version = (entry.version or 1) + 1
    uid = (
        user.get("upn")
        or user.get("preferred_username")
        or user.get("email")
        or user.get("unique_name")
        or "admin"
    )
    entry.last_updated_by = uid
    entry.last_updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(entry)
    return entry
