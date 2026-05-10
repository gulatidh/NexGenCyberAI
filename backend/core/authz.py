"""
RBAC for the portal.

Roles (ascending privilege):
  - reader  : can GET any resource within the grant's scope
  - editor  : reader + create / update / delete within scope
  - admin   : editor + manage user grants (the "User Access Administrator")

Scopes:
  - global              : applies to everything
  - client / <id>       : applies to that client + every project under it
  - project / <id>      : applies only to that project

Effective role for any (scope_type, scope_id) is the max role across all grants
that cover it (project ⊆ client ⊆ global).
"""
from __future__ import annotations
from typing import Iterable, List, Optional, Set

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from api.models.models import AccessRole, AccessScope, Project, UserAccess
from db.database import get_db
from core.security import get_current_user


_RANK = {AccessRole.READER: 1, AccessRole.EDITOR: 2, AccessRole.ADMIN: 3}


def _normalize_email(s: str) -> str:
    return (s or "").strip().lower()


def _user_email(user: dict) -> str:
    """Pick a stable identifier for the caller. UPN is preferred but Entra
    sometimes returns it under preferred_username or email."""
    return _normalize_email(
        user.get("upn")
        or user.get("preferred_username")
        or user.get("email")
        or user.get("unique_name", "")
    )


def get_user_grants(db: Session, email: str) -> List[UserAccess]:
    """Return all grants for an email (case-insensitive)."""
    e = _normalize_email(email)
    if not e:
        return []
    return db.query(UserAccess).filter(UserAccess.email == e).all()


def effective_role(
    grants: Iterable[UserAccess],
    scope_type: AccessScope,
    scope_id: Optional[str] = None,
    db: Optional[Session] = None,
) -> Optional[AccessRole]:
    """Highest-privilege role applicable to (scope_type, scope_id).

    Project scope inherits from its parent Client (resolved via DB) and global.
    Client scope inherits from global.
    """
    parent_client_id: Optional[str] = None
    if scope_type == AccessScope.PROJECT and scope_id and db is not None:
        proj = db.query(Project).filter(Project.id == scope_id).first()
        if proj:
            parent_client_id = proj.client_id

    best: Optional[AccessRole] = None
    for g in grants:
        applies = False
        if g.scope_type == AccessScope.GLOBAL:
            applies = True
        elif g.scope_type == AccessScope.CLIENT:
            if scope_type == AccessScope.CLIENT and g.scope_id == scope_id:
                applies = True
            elif scope_type == AccessScope.PROJECT and g.scope_id == parent_client_id:
                applies = True
        elif g.scope_type == AccessScope.PROJECT:
            if scope_type == AccessScope.PROJECT and g.scope_id == scope_id:
                applies = True

        if applies:
            if best is None or _RANK[g.role] > _RANK[best]:
                best = g.role
    return best


def has_role(grants: Iterable[UserAccess], required: AccessRole,
             scope_type: AccessScope = AccessScope.GLOBAL,
             scope_id: Optional[str] = None,
             db: Optional[Session] = None) -> bool:
    eff = effective_role(grants, scope_type, scope_id, db=db)
    if eff is None:
        return False
    return _RANK[eff] >= _RANK[required]


def require_role(min_role: AccessRole):
    """Build a FastAPI dependency that enforces a global-scope role.

    For per-resource scoping (e.g. editor on a specific project), endpoints
    should call effective_role / has_role directly with the resolved scope.
    """
    def _dep(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
        email = _user_email(user)
        if not email:
            raise HTTPException(status_code=401, detail="Could not identify user")
        grants = get_user_grants(db, email)
        if not has_role(grants, min_role, scope_type=AccessScope.GLOBAL, db=db):
            raise HTTPException(status_code=403, detail=f"{min_role.value} role required")
        return user
    return _dep


def require_scoped_role(min_role: AccessRole, scope_type: AccessScope, scope_id: str,
                        db: Session, user: dict) -> None:
    """Throw 403 if the caller's effective role at (scope_type, scope_id) is
    below min_role. Helper for endpoints that need per-resource checks."""
    email = _user_email(user)
    if not email:
        raise HTTPException(status_code=401, detail="Could not identify user")
    grants = get_user_grants(db, email)
    if not has_role(grants, min_role, scope_type=scope_type, scope_id=scope_id, db=db):
        raise HTTPException(status_code=403, detail=f"{min_role.value} required at {scope_type.value} scope")


def is_admin_anywhere(grants: Iterable[UserAccess]) -> bool:
    """True if the caller holds admin role at any scope — used to gate the
    Admin nav and access management endpoints for scoped admins."""
    return any(g.role == AccessRole.ADMIN for g in grants)


def can_manage_scope(
    grants: Iterable[UserAccess],
    target_scope_type: AccessScope,
    target_scope_id: Optional[str],
    db: Session,
) -> bool:
    """True if the caller can grant/revoke roles at the target scope.

    Rule: caller needs admin at a scope that *covers* the target.
      - Target GLOBAL          → caller needs GLOBAL admin
      - Target CLIENT X        → caller needs GLOBAL admin OR admin at CLIENT X
      - Target PROJECT P (in X)→ caller needs GLOBAL admin, admin at CLIENT X, or admin at PROJECT P
    """
    return has_role(grants, AccessRole.ADMIN,
                    scope_type=target_scope_type, scope_id=target_scope_id, db=db)


def manageable_scope_ids(grants: Iterable[UserAccess], db: Session) -> dict:
    """Return the scopes a caller can manage grants on. Used by the SPA to
    constrain the Grant dialog dropdowns to only what the caller can act on.

    Returns: {"global": bool, "client_ids": [str], "project_ids": [str]}
    """
    out = {"global": False, "client_ids": set(), "project_ids": set()}
    if any(g.role == AccessRole.ADMIN and g.scope_type == AccessScope.GLOBAL for g in grants):
        out["global"] = True
    for g in grants:
        if g.role != AccessRole.ADMIN:
            continue
        if g.scope_type == AccessScope.CLIENT and g.scope_id:
            out["client_ids"].add(g.scope_id)
        elif g.scope_type == AccessScope.PROJECT and g.scope_id:
            out["project_ids"].add(g.scope_id)
    # Client admins implicitly manage every project under their client.
    if out["client_ids"]:
        for p in db.query(Project).filter(Project.client_id.in_(list(out["client_ids"]))).all():
            out["project_ids"].add(p.id)
    return {
        "global": out["global"],
        "client_ids": sorted(out["client_ids"]),
        "project_ids": sorted(out["project_ids"]),
    }
