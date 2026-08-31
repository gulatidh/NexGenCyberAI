"""
Guest Access Tokens — time-limited, read-only portal links with no Azure AD requirement.

Admin endpoints (require normal auth):
  POST   /guest-tokens/              create a new token
  GET    /guest-tokens/              list all tokens for a client
  DELETE /guest-tokens/{id}          revoke a token

Public endpoint (no auth):
  GET    /public/guest/{token}       validate token and return a short-lived guest JWT
  GET    /public/guest/{token}/info  return label/expiry/scope for the landing page (no JWT)
"""
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import get_db
from core.security import get_current_user
from core.config import get_settings

settings = get_settings()

router = APIRouter(tags=["guest-tokens"])


# ── helpers ────────────────────────────────────────────────────────────────────

def _guest_secret() -> str:
    """Use SECRET_KEY + a fixed suffix so we don't need a new env var."""
    return settings.SECRET_KEY + ":guest"


def _issue_guest_jwt(token_row) -> str:
    """Mint a short-lived JWT the frontend stores in sessionStorage."""
    from api.models.models import Client, Project
    now = datetime.now(timezone.utc)
    # Guest session lasts until token expiry (max 24 h per issuance)
    exp = min(token_row.expires_at, now + timedelta(hours=24))
    payload = {
        "sub": f"guest:{token_row.id}",
        "guest": True,
        "token_id": token_row.id,
        "client_id": token_row.client_id,
        "project_id": token_row.project_id,
        "label": token_row.label,
        "iat": now,
        "exp": exp,
    }
    return pyjwt.encode(payload, _guest_secret(), algorithm="HS256")


def _decode_guest_jwt(token: str) -> dict:
    try:
        return pyjwt.decode(token, _guest_secret(), algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Guest session expired — request a new link")
    except pyjwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid guest token: {e}")


# ── schemas ────────────────────────────────────────────────────────────────────

class GuestTokenCreate(BaseModel):
    label: str
    client_id: str
    project_id: Optional[str] = None
    expires_at: datetime          # ISO 8601 with timezone from the UI
    note: Optional[str] = None


class GuestTokenOut(BaseModel):
    id: str
    label: str
    client_id: str
    project_id: Optional[str]
    expires_at: datetime
    created_by: str
    created_at: datetime
    last_used_at: Optional[datetime]
    is_revoked: bool
    is_expired: bool
    note: Optional[str]
    portal_url: str


def _out(row, request_base: str = "") -> dict:
    now = datetime.now(timezone.utc)
    exp = row.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return {
        "id": row.id,
        "label": row.label,
        "client_id": row.client_id,
        "project_id": row.project_id,
        "expires_at": exp,
        "created_by": row.created_by,
        "created_at": row.created_at,
        "last_used_at": row.last_used_at,
        "is_revoked": row.is_revoked,
        "is_expired": exp < now,
        "note": row.note,
        "portal_url": f"{request_base}/guest/{row.token}",
    }


# ── admin endpoints ────────────────────────────────────────────────────────────

@router.post("/guest-tokens/", response_model=dict)
async def create_guest_token(
    body: GuestTokenCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    from api.models.models import GuestToken, Client, Project
    # Validate client exists
    if not db.query(Client.id).filter(Client.id == body.client_id).first():
        raise HTTPException(status_code=404, detail="Client not found")
    if body.project_id:
        if not db.query(Project.id).filter(
            Project.id == body.project_id, Project.client_id == body.client_id
        ).first():
            raise HTTPException(status_code=404, detail="Project not found for this client")

    exp = body.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="expires_at must be in the future")

    email = (user.get("upn") or user.get("preferred_username") or user.get("email") or "unknown").lower()
    row = GuestToken(
        token=secrets.token_hex(32),
        label=body.label.strip(),
        client_id=body.client_id,
        project_id=body.project_id or None,
        expires_at=exp,
        created_by=email,
        note=(body.note or "").strip() or None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _out(row)


@router.get("/guest-tokens/", response_model=List[dict])
async def list_guest_tokens(
    client_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    from api.models.models import GuestToken
    q = db.query(GuestToken)
    if client_id:
        q = q.filter(GuestToken.client_id == client_id)
    rows = q.order_by(GuestToken.created_at.desc()).limit(200).all()
    return [_out(r) for r in rows]


@router.delete("/guest-tokens/{token_id}")
async def revoke_guest_token(
    token_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    from api.models.models import GuestToken
    row = db.query(GuestToken).filter(GuestToken.id == token_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Token not found")
    row.is_revoked = True
    db.commit()
    return {"ok": True}


# ── public endpoints (no auth) ─────────────────────────────────────────────────

@router.get("/public/guest/{token}/info")
async def guest_token_info(token: str, db: Session = Depends(get_db)):
    """Return label, scope, expiry — shown on the landing page before accepting."""
    from api.models.models import GuestToken, Client, Project
    row = db.query(GuestToken).filter(GuestToken.token == token).first()
    if not row:
        raise HTTPException(status_code=404, detail="Invalid or expired guest link")

    now = datetime.now(timezone.utc)
    exp = row.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)

    if row.is_revoked:
        raise HTTPException(status_code=403, detail="This guest link has been revoked")
    if exp < now:
        raise HTTPException(status_code=403, detail="This guest link has expired")

    client = db.query(Client).filter(Client.id == row.client_id).first()
    project = db.query(Project).filter(Project.id == row.project_id).first() if row.project_id else None

    return {
        "label": row.label,
        "note": row.note,
        "client_name": client.name if client else row.client_id,
        "project_name": project.name if project else None,
        "expires_at": exp.isoformat(),
        "scope": "project" if row.project_id else "account",
    }


@router.get("/public/guest/{token}")
async def redeem_guest_token(token: str, db: Session = Depends(get_db)):
    """Validate a raw token and return a short-lived guest JWT for the frontend."""
    from api.models.models import GuestToken
    row = db.query(GuestToken).filter(GuestToken.token == token).first()
    if not row:
        raise HTTPException(status_code=404, detail="Invalid or expired guest link")

    now = datetime.now(timezone.utc)
    exp = row.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)

    if row.is_revoked:
        raise HTTPException(status_code=403, detail="This guest link has been revoked")
    if exp < now:
        raise HTTPException(status_code=403, detail="This guest link has expired")

    row.last_used_at = now
    db.commit()

    return {
        "access_token": _issue_guest_jwt(row),
        "token_type": "bearer",
        "expires_at": exp.isoformat(),
        "client_id": row.client_id,
        "project_id": row.project_id,
        "label": row.label,
    }
