"""SSO / Azure Entra ID settings.

- GET  /sso/config/   : current config (secret never echoed)
- PATCH /sso/config/  : admin-only upsert
- POST /sso/test/     : admin-only connectivity check against the tenant
"""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.security import get_current_user
from core.authz import require_role, _user_email
from db.database import get_db
from api.models.models import AccessRole
from services.sso_settings import get_config_safe, update_config

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/sso", tags=["sso"])


class SsoConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None
    authority: Optional[str] = None


@router.get("/config/")
async def get_sso_config(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return get_config_safe(db)


@router.patch("/config/")
async def update_sso_config(
    payload: SsoConfigUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_role(AccessRole.ADMIN)),
):
    update_config(db, payload.model_dump(exclude_unset=True), updated_by=_user_email(user))
    return get_config_safe(db)


@router.post("/test/")
async def test_sso_connection(
    db: Session = Depends(get_db),
    user=Depends(require_role(AccessRole.ADMIN)),
):
    """Verify the tenant is reachable via OpenID Connect discovery endpoint."""
    import httpx
    cfg = get_config_safe(db)
    tenant_id = cfg.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Tenant ID is not configured")
    url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "success": True,
                "message": f"Tenant reachable — issuer: {data.get('issuer', 'unknown')}",
                "issuer": data.get("issuer"),
                "token_endpoint": data.get("token_endpoint"),
            }
        return {
            "success": False,
            "message": f"Tenant returned HTTP {resp.status_code} — check your Tenant ID",
        }
    except Exception as exc:
        return {"success": False, "message": f"Connection failed: {exc}"}
