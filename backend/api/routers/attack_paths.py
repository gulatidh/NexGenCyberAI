"""Attack path graph endpoint."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Optional

from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/attack-paths", tags=["attack-paths"])


@router.get("/")
async def get_attack_paths(
    client_id: str,
    scan_id: Optional[str] = None,
    project_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return nodes and edges for the attack path visualisation."""
    from services.attack_path import get_attack_paths as _get
    return _get(db, client_id, scan_id=scan_id, project_id=project_id)
