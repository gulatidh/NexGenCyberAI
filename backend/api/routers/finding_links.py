"""Finding-to-finding relationship endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel
from api.models.models import FindingLink, Finding
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

router = APIRouter(prefix="/clients/{client_id}/findings", tags=["finding-links"])

VALID_LINK_TYPES = {"causes", "mitigates", "supersedes", "related"}


class FindingLinkCreate(BaseModel):
    from_finding_id: str
    to_finding_id: str
    link_type: str
    notes: Optional[str] = None


@router.get("/{finding_id}/links")
async def get_finding_links(
    client_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get all links where this finding is the source OR target."""
    from_links = db.query(FindingLink).filter(
        FindingLink.client_id == client_id,
        FindingLink.from_finding_id == finding_id,
    ).all()
    to_links = db.query(FindingLink).filter(
        FindingLink.client_id == client_id,
        FindingLink.to_finding_id == finding_id,
    ).all()

    def _enrich(link, direction):
        other_id = link.to_finding_id if direction == "outbound" else link.from_finding_id
        other = db.query(Finding).filter(Finding.id == other_id).first()
        return {
            "id": link.id,
            "link_type": link.link_type,
            "direction": direction,
            "notes": link.notes,
            "created_by": link.created_by,
            "created_at": link.created_at.isoformat() if link.created_at else None,
            "other_finding": {
                "id": other.id,
                "title": other.title,
                "severity": other.severity.value if hasattr(other.severity, "value") else str(other.severity),
                "status": other.status,
                "resource_id": other.resource_id,
            } if other else None,
        }

    return {
        "finding_id": finding_id,
        "links": (
            [_enrich(l, "outbound") for l in from_links] +
            [_enrich(l, "inbound") for l in to_links]
        ),
    }


@router.post("/{finding_id}/links", dependencies=[Depends(require_editor_anywhere)])
async def create_finding_link(
    client_id: str,
    finding_id: str,
    payload: FindingLinkCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    if payload.link_type not in VALID_LINK_TYPES:
        raise HTTPException(status_code=400, detail=f"link_type must be one of {VALID_LINK_TYPES}")
    if payload.from_finding_id == payload.to_finding_id:
        raise HTTPException(status_code=400, detail="Cannot link a finding to itself")

    for fid in (payload.from_finding_id, payload.to_finding_id):
        f = db.query(Finding).filter(Finding.id == fid).first()
        if not f:
            raise HTTPException(status_code=404, detail=f"Finding {fid} not found")

    link = FindingLink(
        client_id=client_id,
        from_finding_id=payload.from_finding_id,
        to_finding_id=payload.to_finding_id,
        link_type=payload.link_type,
        created_by=user.get("preferred_username") or user.get("email") or "manual",
        notes=payload.notes,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return {"id": link.id, "created": True}


@router.delete("/links/{link_id}", dependencies=[Depends(require_editor_anywhere)])
async def delete_finding_link(
    client_id: str,
    link_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    link = db.query(FindingLink).filter(
        FindingLink.id == link_id,
        FindingLink.client_id == client_id,
    ).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    db.delete(link)
    db.commit()
    return {"deleted": True}
