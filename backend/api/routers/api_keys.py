"""API key management — create, list, revoke programmatic access keys."""
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.models.models import APIKey
from api.schemas.schemas import APIKeyCreate, APIKeyResponse, APIKeyCreated
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere, require_scoped_role, AccessRole, AccessScope

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.get("/", response_model=List[APIKeyResponse])
async def list_api_keys(client_id: Optional[str] = None, db: Session = Depends(get_db), user=Depends(get_current_user)):
    if client_id:
        require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    q = db.query(APIKey).filter(APIKey.is_active == True)
    if client_id:
        q = q.filter(APIKey.client_id == client_id)
    return q.order_by(APIKey.created_at.desc()).all()


@router.post("/", response_model=APIKeyCreated, dependencies=[Depends(require_editor_anywhere)])
async def create_api_key(payload: APIKeyCreate, db: Session = Depends(get_db), user=Depends(get_current_user)):
    if payload.client_id:
        require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, payload.client_id, db, user)
    full_key = "owlet_" + secrets.token_hex(32)
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    expires_at = None
    if payload.expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_days)

    key = APIKey(
        client_id=payload.client_id,
        name=payload.name,
        key_hash=key_hash,
        key_prefix=full_key[:12],
        created_by=user.get("email") or user.get("preferred_username") or "",
        scopes=payload.scopes,
        expires_at=expires_at,
    )
    db.add(key)
    db.commit()
    db.refresh(key)

    result = APIKeyCreated.model_validate(key)
    result.full_key = full_key
    return result


@router.delete("/{key_id}", dependencies=[Depends(require_editor_anywhere)])
async def revoke_api_key(key_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    key = db.query(APIKey).filter(APIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    if key.client_id:
        require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, key.client_id, db, user)
    key.is_active = False
    db.commit()
    return {"revoked": True}
