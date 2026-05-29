"""Admin endpoints: list users, manage RBAC grants, expose caller's effective access."""
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from api.models.models import AccessRole, AccessScope, Client, Project, UserAccess
from api.schemas.schemas import (
    GrantCreate, GrantResponse, MyAccessResponse, UserAccessSummary,
)
from db.database import get_db
from core.security import get_current_user
from core.authz import (
    _normalize_email, _user_email, effective_role, get_user_grants, require_role,
    is_admin_anywhere, can_manage_scope, manageable_scope_ids,
)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/sync/feeds")
async def list_sync_feeds(_=Depends(get_current_user)):
    """Every registered external feed with last-sync timestamp + count.
    Powers the Sync page tile grid."""
    from services.sync_feeds import list_feeds
    return list_feeds()


@router.post("/sync/feeds/{feed_id}/refresh")
async def refresh_sync_feed(feed_id: str, _=Depends(get_current_user)):
    """Manually sync one feed (EPSS / KEV / NVD / Frameworks)."""
    from services.sync_feeds import sync_feed
    return sync_feed(feed_id)


@router.post("/sync/feeds/refresh-all")
async def refresh_all_sync_feeds(_=Depends(get_current_user)):
    """Sync every feed sequentially. Returns per-feed results."""
    from services.sync_feeds import REGISTRY, sync_feed
    results = []
    for fid in REGISTRY.keys():
        results.append(sync_feed(fid))
    return {"results": results}


# Back-compat aliases for the older endpoint names (used by earlier UI builds).
@router.get("/threat-intel/stats")
async def threat_intel_stats(_=Depends(get_current_user)):
    from services.threat_intel import stats
    return stats()


@router.post("/threat-intel/refresh")
async def threat_intel_refresh(force: bool = True, _=Depends(get_current_user)):
    from services.threat_intel import refresh_all
    return refresh_all(force=force)


def _scope_label(scope_type: AccessScope, scope_id: Optional[str], db: Session) -> Optional[str]:
    if scope_type == AccessScope.GLOBAL:
        return "Global"
    if scope_type == AccessScope.CLIENT and scope_id:
        c = db.query(Client).filter(Client.id == scope_id).first()
        return c.name if c else scope_id
    if scope_type == AccessScope.PROJECT and scope_id:
        p = db.query(Project).filter(Project.id == scope_id).first()
        if p:
            client = db.query(Client).filter(Client.id == p.client_id).first()
            return f"{client.name if client else '?'} — {p.name}"
        return scope_id
    return None


def _grant_response(g: UserAccess, db: Session) -> GrantResponse:
    return GrantResponse(
        id=g.id, email=g.email, role=g.role,
        scope_type=g.scope_type, scope_id=g.scope_id,
        scope_label=_scope_label(g.scope_type, g.scope_id, db),
        granted_by=g.granted_by, granted_at=g.granted_at,
    )


@router.get("/me", response_model=MyAccessResponse)
async def get_my_access(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Caller's own grants — used by the SPA to gate the Admin nav item and
    decide whether write actions are visible. Always succeeds for an
    authenticated user, even if they have no grants."""
    email = _user_email(user)
    grants = get_user_grants(db, email)
    eff_global = effective_role(grants, AccessScope.GLOBAL, db=db)
    is_admin = eff_global == AccessRole.ADMIN
    is_editor_anywhere = any(g.role in (AccessRole.EDITOR, AccessRole.ADMIN) for g in grants)
    return MyAccessResponse(
        email=email,
        grants=[_grant_response(g, db) for g in grants],
        is_admin=is_admin,
        is_admin_anywhere=is_admin_anywhere(grants),
        is_editor_anywhere=is_editor_anywhere,
        manageable_scopes=manageable_scope_ids(grants, db),
    )


def _require_admin_anywhere(user: dict = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    """Allow any user holding admin role at *any* scope — used to gate access
    management endpoints that scoped admins also need (with per-target checks
    inside the handler)."""
    email = _user_email(user)
    if not email:
        raise HTTPException(status_code=401, detail="Could not identify user")
    grants = get_user_grants(db, email)
    if not is_admin_anywhere(grants):
        raise HTTPException(status_code=403, detail="admin role required (at any scope)")
    return user


@router.get("/users", response_model=List[UserAccessSummary])
async def list_users_with_grants(
    db: Session = Depends(get_db),
    user: dict = Depends(_require_admin_anywhere),
):
    """List users + grants. Global admins see everyone; scoped admins only see
    grants at scopes they can manage."""
    caller_email = _user_email(user)
    caller_grants = get_user_grants(db, caller_email)
    is_global = any(
        g.role == AccessRole.ADMIN and g.scope_type == AccessScope.GLOBAL for g in caller_grants
    )

    rows = db.query(UserAccess).order_by(UserAccess.email.asc(), UserAccess.granted_at.desc()).all()
    if not is_global:
        # Scoped admin → only return grants at scopes they can manage.
        rows = [g for g in rows if can_manage_scope(caller_grants, g.scope_type, g.scope_id, db)]

    by_email: Dict[str, List[UserAccess]] = defaultdict(list)
    for g in rows:
        by_email[g.email].append(g)
    out: List[UserAccessSummary] = []
    for email, grants in by_email.items():
        out.append(UserAccessSummary(
            email=email,
            grants=[_grant_response(g, db) for g in grants],
            effective_global_role=effective_role(grants, AccessScope.GLOBAL, db=db),
        ))
    return out


@router.post("/grants", response_model=GrantResponse, status_code=201)
async def create_grant(
    payload: GrantCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(_require_admin_anywhere),
):
    email = _normalize_email(payload.email)
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email/UPN is required")

    if payload.scope_type == AccessScope.GLOBAL:
        if payload.scope_id is not None:
            raise HTTPException(status_code=400, detail="scope_id must be omitted for global scope")
    else:
        if not payload.scope_id:
            raise HTTPException(status_code=400, detail=f"scope_id required for {payload.scope_type.value} scope")
        if payload.scope_type == AccessScope.CLIENT:
            if not db.query(Client).filter(Client.id == payload.scope_id).first():
                raise HTTPException(status_code=404, detail="Client not found")
        elif payload.scope_type == AccessScope.PROJECT:
            if not db.query(Project).filter(Project.id == payload.scope_id).first():
                raise HTTPException(status_code=404, detail="Project not found")

    # Caller must hold admin at a scope that *covers* the target.
    caller_grants = get_user_grants(db, _user_email(user))
    if not can_manage_scope(caller_grants, payload.scope_type, payload.scope_id, db):
        raise HTTPException(
            status_code=403,
            detail=f"Admin role at {payload.scope_type.value} scope (or higher) required to grant here.",
        )

    grant = UserAccess(
        email=email,
        role=payload.role,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        granted_by=_user_email(user),
        granted_at=datetime.now(timezone.utc),
    )
    db.add(grant)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="This grant already exists for the user")
    db.refresh(grant)
    return _grant_response(grant, db)


@router.delete("/grants/{grant_id}", status_code=204)
async def delete_grant(
    grant_id: str,
    db: Session = Depends(get_db),
    user: dict = Depends(_require_admin_anywhere),
):
    g = db.query(UserAccess).filter(UserAccess.id == grant_id).first()
    if not g:
        raise HTTPException(status_code=404, detail="Grant not found")

    # Caller must hold admin at a scope that covers the grant being revoked.
    caller_email = _user_email(user)
    caller_grants = get_user_grants(db, caller_email)
    if not can_manage_scope(caller_grants, g.scope_type, g.scope_id, db):
        raise HTTPException(
            status_code=403,
            detail=f"Admin role at {g.scope_type.value} scope (or higher) required to revoke here.",
        )

    # Safety: never let the last global admin revoke themselves.
    if (
        g.email == caller_email
        and g.role == AccessRole.ADMIN
        and g.scope_type == AccessScope.GLOBAL
    ):
        remaining = db.query(UserAccess).filter(
            UserAccess.role == AccessRole.ADMIN,
            UserAccess.scope_type == AccessScope.GLOBAL,
            UserAccess.id != grant_id,
        ).count()
        if remaining == 0:
            raise HTTPException(
                status_code=409,
                detail="Cannot revoke the last global admin — grant another user admin first.",
            )
    db.delete(g)
    db.commit()
