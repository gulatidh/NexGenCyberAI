"""Runner Registry — cloud-side endpoints for local runner pairing and heartbeat.

Flow:
  1. Admin calls POST /runner-registry/tokens  →  gets a bearer token (shown once)
  2. Local runner calls POST /runner-registry/register with that token  →  registration created
  3. Local runner calls PATCH /runner-registry/runners/{id}/heartbeat periodically
  4. Admin views all runners at GET /runner-registry/runners
"""

import hashlib, secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import get_db
from core.security import get_current_user
from api.models.models import LocalRunnerRegistration

router = APIRouter(prefix="/runner-registry", tags=["runner-registry"])

_TOKEN_PREFIX = "owlet_runner_"
_STALE_HOURS  = 2   # last_seen_at older than this → stale
_OFFLINE_HOURS = 24  # older than this → offline


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _make_token() -> str:
    return _TOKEN_PREFIX + secrets.token_hex(32)


def _age_status(last_seen: Optional[datetime]) -> str:
    if not last_seen:
        return "pending"
    delta = datetime.now(timezone.utc) - last_seen
    if delta.total_seconds() < _STALE_HOURS * 3600:
        return "active"
    if delta.total_seconds() < _OFFLINE_HOURS * 3600:
        return "stale"
    return "offline"


def _row_to_dict(r: LocalRunnerRegistration) -> dict:
    import json
    tools = []
    if r.tools_json:
        try:
            tools = json.loads(r.tools_json)
        except Exception:
            pass
    return {
        "id": r.id,
        "name": r.name,
        "token_prefix": r.token_prefix,
        "machine_name": r.machine_name,
        "owlet_version": r.owlet_version,
        "is_kali": r.is_kali,
        "status": _age_status(r.last_seen_at),
        "registered_at": r.registered_at.isoformat() if r.registered_at else None,
        "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
        "token_expires_at": r.token_expires_at.isoformat() if r.token_expires_at else None,
        "created_by": r.created_by,
        "tools": tools,
        "installed_count": sum(1 for t in tools if t.get("installed")),
        "local_count": sum(1 for t in tools if t.get("mode") == "local"),
    }


# ── Auth helper for token-based (unauthenticated) endpoints ───────────────────

def _get_registration_by_token(token: str, db: Session) -> LocalRunnerRegistration:
    h = _hash(token)
    reg = db.query(LocalRunnerRegistration).filter(
        LocalRunnerRegistration.token_hash == h
    ).first()
    if not reg:
        raise HTTPException(401, "Invalid runner token")
    if reg.token_expires_at and reg.token_expires_at < datetime.now(timezone.utc):
        raise HTTPException(401, "Runner token has expired")
    return reg


# ── Schemas ───────────────────────────────────────────────────────────────────

class CreateTokenRequest(BaseModel):
    name: str                          # descriptive label, e.g. "dheeraj-kali-laptop"
    expires_days: Optional[int] = None  # None = never expires


class RegisterRequest(BaseModel):
    machine_name: Optional[str] = None
    owlet_version: Optional[str] = None
    is_kali: bool = False
    tools: Optional[list] = None       # list of tool status dicts


class HeartbeatRequest(BaseModel):
    tools: Optional[list] = None
    owlet_version: Optional[str] = None


# ── Cloud-side endpoints (JWT-authenticated) ──────────────────────────────────

@router.post("/tokens")
async def create_token(
    body: CreateTokenRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Generate a pairing token. Show it once — it's not recoverable."""
    token = _make_token()
    expires = (
        datetime.now(timezone.utc) + timedelta(days=body.expires_days)
        if body.expires_days else None
    )
    uid = (user.get("sub") or user.get("upn") or user.get("email") or "") if isinstance(user, dict) else ""
    reg = LocalRunnerRegistration(
        name=body.name,
        token_hash=_hash(token),
        token_prefix=token[:20],
        created_by=uid,
        status="pending",
        token_expires_at=expires,
    )
    db.add(reg)
    db.commit()
    db.refresh(reg)
    return {
        "id": reg.id,
        "name": reg.name,
        "token": token,           # shown once only
        "token_prefix": reg.token_prefix,
        "expires_at": expires.isoformat() if expires else None,
        "instruction": (
            f"On your local runner machine, run:\n"
            f"  curl -X POST http://localhost:8000/api/v1/local-runner/cloud/link \\\n"
            f"    -H 'Content-Type: application/json' \\\n"
            f"    -d '{{\"cloud_url\":\"https://owlet-api.azurewebsites.net\",\"token\":\"{token}\"}}'"
        ),
    }


@router.get("/tokens")
async def list_tokens(db: Session = Depends(get_db), _=Depends(get_current_user)):
    rows = db.query(LocalRunnerRegistration).order_by(LocalRunnerRegistration.created_at.desc()).all()
    return [_row_to_dict(r) for r in rows]


@router.delete("/tokens/{runner_id}")
async def revoke_token(runner_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    reg = db.query(LocalRunnerRegistration).filter(LocalRunnerRegistration.id == runner_id).first()
    if not reg:
        raise HTTPException(404)
    db.delete(reg)
    db.commit()
    return {"ok": True}


@router.get("/runners")
async def list_runners(db: Session = Depends(get_db), _=Depends(get_current_user)):
    rows = db.query(LocalRunnerRegistration).order_by(LocalRunnerRegistration.last_seen_at.desc()).all()
    return [_row_to_dict(r) for r in rows]


@router.get("/runners/{runner_id}")
async def get_runner(runner_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    reg = db.query(LocalRunnerRegistration).filter(LocalRunnerRegistration.id == runner_id).first()
    if not reg:
        raise HTTPException(404)
    return _row_to_dict(reg)


# ── Token-authenticated endpoints (called by the local runner, no JWT) ────────

@router.post("/register")
async def register(
    body: RegisterRequest,
    authorization: str = Header(..., alias="Authorization"),
    db: Session = Depends(get_db),
):
    """Called by the local runner with the pairing token to complete registration."""
    token = authorization.removeprefix("Bearer ").strip()
    reg = _get_registration_by_token(token, db)
    import json
    now = datetime.now(timezone.utc)
    reg.machine_name = body.machine_name or reg.machine_name
    reg.owlet_version = body.owlet_version or reg.owlet_version
    reg.is_kali = body.is_kali
    reg.tools_json = json.dumps(body.tools or [])
    reg.status = "active"
    if not reg.registered_at:
        reg.registered_at = now
    reg.last_seen_at = now
    db.commit()
    return {
        "ok": True,
        "runner_id": reg.id,
        "name": reg.name,
        "message": f"Runner '{reg.name}' registered successfully.",
    }


@router.patch("/runners/{runner_id}/heartbeat")
async def heartbeat(
    runner_id: str,
    body: HeartbeatRequest,
    authorization: str = Header(..., alias="Authorization"),
    db: Session = Depends(get_db),
):
    """Periodic status update from the local runner."""
    token = authorization.removeprefix("Bearer ").strip()
    reg = _get_registration_by_token(token, db)
    if reg.id != runner_id:
        raise HTTPException(403, "Token does not match this runner")
    import json
    reg.last_seen_at = datetime.now(timezone.utc)
    reg.status = "active"
    if body.tools is not None:
        reg.tools_json = json.dumps(body.tools)
    if body.owlet_version:
        reg.owlet_version = body.owlet_version
    db.commit()
    return {"ok": True, "last_seen_at": reg.last_seen_at.isoformat()}
