"""Changelog entries — auto-generated on startup from git commits + LLM."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from api.models.models import ChangelogEntry
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/changelog", tags=["changelog"])


@router.get("/", response_model=List[dict])
async def list_changelog(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    entries = (
        db.query(ChangelogEntry)
        .order_by(ChangelogEntry.deployed_at.desc())
        .limit(50)
        .all()
    )
    result = []
    for e in entries:
        result.append({
            "id": e.id,
            "commit_sha": e.commit_sha,
            "version_label": e.version_label,
            "summary": e.summary,
            "raw_commits": e.raw_commits,
            "deployed_at": e.deployed_at.isoformat() if e.deployed_at else None,
        })
    return result
