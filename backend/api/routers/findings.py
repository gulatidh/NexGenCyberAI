"""Global findings endpoints (across all scans for a client)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from api.models.models import Finding, Scan, FrameworkType
from api.schemas.schemas import FindingResponse, FindingUpdate
from db.database import get_db
from core.security import get_current_user
from fastapi import HTTPException
from services.compliance import recompute_client_framework

router = APIRouter(prefix="/clients/{client_id}/findings", tags=["findings"])


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    client_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
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
    return q.order_by(desc(Finding.cvss_score), desc(Finding.created_at)).limit(200).all()


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
