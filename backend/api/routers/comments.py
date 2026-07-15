"""Comments on security entities (finding, risk, remediation_action, threat_entry)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.models.models import Comment
from api.schemas.schemas import CommentCreate, CommentResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

router = APIRouter(prefix="/clients/{client_id}/comments", tags=["comments"])


@router.get("/", response_model=List[CommentResponse])
async def list_comments(
    client_id: str,
    entity_type: str,
    entity_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    return (
        db.query(Comment)
        .filter(
            Comment.client_id == client_id,
            Comment.entity_type == entity_type,
            Comment.entity_id == entity_id,
        )
        .order_by(Comment.created_at.asc())
        .all()
    )


@router.post("/", response_model=CommentResponse, dependencies=[Depends(require_editor_anywhere)])
async def create_comment(
    client_id: str,
    payload: CommentCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    comment = Comment(
        client_id=client_id,
        entity_type=payload.entity_type,
        entity_id=payload.entity_id,
        author_email=user.get("email") or user.get("preferred_username") or "unknown",
        author_name=user.get("name") or "",
        body=payload.body,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


@router.patch("/{comment_id}", response_model=CommentResponse, dependencies=[Depends(require_editor_anywhere)])
async def update_comment(
    client_id: str,
    comment_id: str,
    body: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    comment = db.query(Comment).filter(Comment.id == comment_id, Comment.client_id == client_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    email = user.get("email") or user.get("preferred_username") or ""
    if comment.author_email != email:
        raise HTTPException(status_code=403, detail="Can only edit your own comments")
    comment.body = body
    db.commit()
    db.refresh(comment)
    return comment


@router.delete("/{comment_id}", dependencies=[Depends(require_editor_anywhere)])
async def delete_comment(
    client_id: str,
    comment_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    comment = db.query(Comment).filter(Comment.id == comment_id, Comment.client_id == client_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    db.delete(comment)
    db.commit()
    return {"deleted": True}


# ── Assignment endpoints (update assignee on finding/risk) ──────────────────────

@router.put("/assign", dependencies=[Depends(require_editor_anywhere)])
async def assign_entity(
    client_id: str,
    entity_type: str,
    entity_id: str,
    assignee_email: str,
    due_date: str = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Set assignee_email (and optionally due_date) on a finding or risk."""
    if entity_type == "finding":
        from api.models.models import Finding, Scan
        obj = (
            db.query(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .filter(Finding.id == entity_id, Scan.client_id == client_id)
            .first()
        )
    elif entity_type == "risk":
        from api.models.models import Risk
        obj = db.query(Risk).filter(Risk.id == entity_id, Risk.client_id == client_id).first()
    else:
        raise HTTPException(status_code=400, detail=f"Assignment not supported for entity_type '{entity_type}'")

    if not obj:
        raise HTTPException(status_code=404, detail=f"{entity_type} not found")

    obj.assignee_email = assignee_email
    if due_date is not None:
        obj.due_date = due_date
    db.commit()
    return {"assigned": True, "assignee_email": assignee_email}
