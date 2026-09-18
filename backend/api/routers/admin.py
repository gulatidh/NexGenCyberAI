"""Admin endpoints: list users, manage RBAC grants, expose caller's effective access."""
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from api.models.models import (
    AccessRole, AccessScope, Client, Project, UserAccess,
    AgentRun, ThreatModel, ScheduledMission,
    ThreatEntry, ControlDeficiency, RemediationAction, MissionLearning,
)
from api.schemas.schemas import (
    GrantCreate, GrantResponse, MyAccessResponse, UserAccessSummary,
)
from db.database import get_db
from core.security import get_current_user
from core.config import get_settings as _get_settings
_settings = _get_settings()
from core.authz import (
    _normalize_email, _user_email, effective_role, get_user_grants, require_role,
    is_admin_anywhere, can_manage_scope, manageable_scope_ids, require_editor_anywhere,
)

router = APIRouter(prefix="/admin", tags=["admin"])

_SOFT_DELETE_RETENTION_DAYS = 30


# ── Deleted client management ─────────────────────────────────────────────────

@router.get("/clients/deleted", dependencies=[Depends(require_role(AccessRole.ADMIN))])
async def list_deleted_clients(db: Session = Depends(get_db)):
    """Global-admin-only: list soft-deleted clients with days remaining before purge."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=_SOFT_DELETE_RETENTION_DAYS)
    rows = (
        db.query(Client)
        .filter(Client.deleted_at.isnot(None))
        .order_by(Client.deleted_at.desc())
        .all()
    )
    result = []
    for c in rows:
        deleted_at = c.deleted_at
        if deleted_at.tzinfo is None:
            deleted_at = deleted_at.replace(tzinfo=timezone.utc)
        days_remaining = max(0, _SOFT_DELETE_RETENTION_DAYS - (datetime.now(timezone.utc) - deleted_at).days)
        result.append({
            "id": c.id,
            "name": c.name,
            "slug": c.slug,
            "industry": c.industry,
            "deleted_at": c.deleted_at.isoformat() if c.deleted_at else None,
            "days_remaining": days_remaining,
            "expires_at": (deleted_at + timedelta(days=_SOFT_DELETE_RETENTION_DAYS)).isoformat(),
            "auto_purge_eligible": deleted_at <= cutoff,
        })
    return result


@router.post("/clients/{client_id}/restore", dependencies=[Depends(require_role(AccessRole.ADMIN))])
async def restore_client(client_id: str, db: Session = Depends(get_db)):
    """Restore a soft-deleted client (only within the 30-day window)."""
    client = db.query(Client).filter(Client.id == client_id, Client.deleted_at.isnot(None)).first()
    if not client:
        raise HTTPException(status_code=404, detail="Deleted client not found")
    deleted_at = client.deleted_at
    if deleted_at.tzinfo is None:
        deleted_at = deleted_at.replace(tzinfo=timezone.utc)
    if (datetime.now(timezone.utc) - deleted_at).days > _SOFT_DELETE_RETENTION_DAYS:
        raise HTTPException(status_code=410, detail="Retention window expired — client cannot be restored")
    client.deleted_at = None
    client.is_active = True
    db.commit()
    return {"id": client.id, "name": client.name, "restored": True}


@router.delete("/clients/{client_id}/permanent", status_code=204,
               dependencies=[Depends(require_role(AccessRole.ADMIN))])
async def permanently_delete_client(client_id: str, db: Session = Depends(get_db)):
    """Permanently and irreversibly delete a soft-deleted client and ALL its data."""
    client = db.query(Client).filter(Client.id == client_id, Client.deleted_at.isnot(None)).first()
    if not client:
        raise HTTPException(status_code=404, detail="Deleted client not found (must be soft-deleted first)")

    # Delete tables not covered by ORM cascade on Client.
    # ScheduledMission is deleted via ORM (not bulk) so its cascade to ScheduledMissionRun fires.
    for sm in db.query(ScheduledMission).filter(ScheduledMission.client_id == client_id).all():
        db.delete(sm)

    # Leaf tables — bulk delete is safe (no children).
    for Model in (MissionLearning, RemediationAction, ControlDeficiency, ThreatEntry, AgentRun, ThreatModel):
        db.query(Model).filter(Model.client_id == client_id).delete(synchronize_session=False)

    # db.delete(client) cascades via ORM:
    #   connectors → assets   (Connector.assets cascade)
    #   scans → findings      (Scan.findings cascade)
    #   framework_assessments (cascade added above)
    #   risks, control_statuses, projects
    db.delete(client)
    db.commit()


@router.post("/clients/purge-expired", dependencies=[Depends(require_role(AccessRole.ADMIN))])
async def purge_expired_clients(db: Session = Depends(get_db)):
    """Manually trigger purge of all clients whose 30-day retention window has expired."""
    return _purge_expired_deleted_clients(db)


def _purge_expired_deleted_clients(db: Session) -> dict:
    """Hard-delete clients soft-deleted more than 30 days ago. Called by scheduler and manual endpoint."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=_SOFT_DELETE_RETENTION_DAYS)
    expired = db.query(Client).filter(
        Client.deleted_at.isnot(None),
        Client.deleted_at <= cutoff,
    ).all()
    count = len(expired)
    for c in expired:
        cid = c.id
        for sm in db.query(ScheduledMission).filter(ScheduledMission.client_id == cid).all():
            db.delete(sm)
        for Model in (MissionLearning, RemediationAction, ControlDeficiency, ThreatEntry, AgentRun, ThreatModel):
            db.query(Model).filter(Model.client_id == cid).delete(synchronize_session=False)
        db.delete(c)
    if count:
        db.commit()
    return {"purged": count}


@router.get("/sync/feeds")
async def list_sync_feeds(_=Depends(get_current_user)):
    """Every registered external feed with last-sync timestamp + count.
    Powers the Sync page tile grid."""
    from services.sync_feeds import list_feeds
    return list_feeds()


@router.post("/sync/feeds/{feed_id}/refresh", dependencies=[Depends(require_editor_anywhere)])
async def refresh_sync_feed(feed_id: str, _=Depends(get_current_user)):
    """Manually sync one feed (EPSS / KEV / NVD / Frameworks)."""
    from services.sync_feeds import sync_feed
    return sync_feed(feed_id)


@router.get("/sync/feeds/{feed_id}/entries")
async def list_sync_feed_entries(
    feed_id: str,
    limit: int = 200,
    q: Optional[str] = None,
    category: Optional[str] = None,
    cwe: Optional[str] = None,
    min_cvss: Optional[float] = None,
    min_score: Optional[float] = None,
    ransomware: bool = False,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Filterable entries for a synced feed (Knowledge Base → Threat
    Intelligence). Returns {id, total, rows[], facets?, note?}; rows carry a
    `ref` external link."""
    from services.sync_feeds import feed_entries
    return feed_entries(
        feed_id, db, limit=min(max(limit, 1), 500), q=q,
        category=category, cwe=cwe, min_cvss=min_cvss, min_score=min_score, ransomware=ransomware,
    )


@router.post("/scan-binaries/cleanup")
async def cleanup_scan_binaries(days: int = 30, _=Depends(get_current_user)):
    """Manually purge uploaded scan binaries older than `days` days.
    Mirrors the daily scheduled cleanup so admins can free disk on demand."""
    from services.scan_binaries import cleanup_old_binaries
    return cleanup_old_binaries(days=days)


@router.post("/sync/feeds/refresh-all", dependencies=[Depends(require_editor_anywhere)])
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


@router.post("/threat-intel/refresh", dependencies=[Depends(require_editor_anywhere)])
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
    authenticated user, even if they have no grants.

    Users listed in INITIAL_ADMIN_EMAILS env var are auto-bootstrapped as
    global admin on first login. Everyone else must be explicitly granted
    access by an existing admin."""
    email = _user_email(user)

    # Auto-bootstrap only for explicitly named initial admins (env var).
    # Never grant based on tenant ID alone — that lets any tenant member in.
    initial_admins = {
        e.strip().lower()
        for e in (_settings.INITIAL_ADMIN_EMAILS or "").split(",")
        if e.strip()
    }
    if email and email in initial_admins:
        existing = db.query(UserAccess).filter(
            UserAccess.email == email,
            UserAccess.scope_type == AccessScope.GLOBAL,
            UserAccess.role == AccessRole.ADMIN,
        ).first()
        if not existing:
            try:
                db.add(UserAccess(
                    email=email,
                    role=AccessRole.ADMIN,
                    scope_type=AccessScope.GLOBAL,
                    scope_id=None,
                    granted_by="initial-admin-bootstrap",
                    granted_at=datetime.now(timezone.utc),
                ))
                db.commit()
            except IntegrityError:
                db.rollback()

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


@router.post("/bootstrap-admin", response_model=MyAccessResponse)
async def bootstrap_admin(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """First-run helper: if there are no global admins in the DB at all, grant
    the caller global admin. Returns 409 if any global admin already exists.
    This lets the first authenticated user self-bootstrap without needing
    INITIAL_ADMIN_UPN to be set."""
    existing_admins = db.query(UserAccess).filter(
        UserAccess.scope_type == AccessScope.GLOBAL,
        UserAccess.role == AccessRole.ADMIN,
    ).count()
    if existing_admins > 0:
        raise HTTPException(status_code=409, detail="Global admin already exists — contact your administrator.")
    email = _user_email(user)
    if not email:
        raise HTTPException(status_code=401, detail="Could not identify user email from token")
    db.add(UserAccess(
        email=email,
        role=AccessRole.ADMIN,
        scope_type=AccessScope.GLOBAL,
        scope_id=None,
        granted_by="bootstrap-admin",
    ))
    db.commit()
    grants = get_user_grants(db, email)
    return MyAccessResponse(
        email=email,
        grants=[_grant_response(g, db) for g in grants],
        is_admin=True,
        is_admin_anywhere=True,
        is_editor_anywhere=True,
        manageable_scopes=[],
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


@router.get("/access-logs/")
async def list_access_logs(
    user_email: Optional[str] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
    since_hours: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    _=Depends(require_role(AccessRole.ADMIN)),
):
    """Global-admin-only audit trail of authenticated portal access — one row
    per API request (who, when, from where, what path + status)."""
    from api.models.models import AccessLog
    q = db.query(AccessLog)
    if user_email:
        q = q.filter(AccessLog.user_email.ilike(f"%{user_email}%"))
    if method:
        q = q.filter(AccessLog.method == method.upper())
    if path:
        q = q.filter(AccessLog.path.ilike(f"%{path}%"))
    if since_hours:
        q = q.filter(AccessLog.created_at >= datetime.now(timezone.utc) - timedelta(hours=int(since_hours)))
    total = q.count()
    limit = max(1, min(int(limit or 100), 500))
    offset = max(0, int(offset or 0))
    rows = q.order_by(AccessLog.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": r.id, "user_email": r.user_email, "user_name": r.user_name,
                "method": r.method, "path": r.path, "status_code": r.status_code,
                "ip_address": r.ip_address, "user_agent": r.user_agent,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@router.get("/prompt-logs")
def list_prompt_logs(
    user_id: Optional[str] = None,
    endpoint: Optional[str] = None,
    status: Optional[str] = None,
    since_hours: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    _=Depends(require_role(AccessRole.ADMIN)),
):
    """Admin-only view of LLM prompt audit log — metadata only, no prompt text stored."""
    from api.models.models import PromptAuditLog
    q = db.query(PromptAuditLog)
    if user_id:
        q = q.filter(PromptAuditLog.user_id.ilike(f"%{user_id}%"))
    if endpoint:
        q = q.filter(PromptAuditLog.endpoint == endpoint)
    if status:
        q = q.filter(PromptAuditLog.status == status)
    if since_hours:
        q = q.filter(PromptAuditLog.created_at >= datetime.now(timezone.utc) - timedelta(hours=int(since_hours)))
    total = q.count()
    limit = max(1, min(int(limit or 100), 500))
    offset = max(0, int(offset or 0))
    rows = q.order_by(PromptAuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": r.id,
                "user_id": r.user_id,
                "client_id": r.client_id,
                "endpoint": r.endpoint,
                "provider": r.provider,
                "model": r.model,
                "input_chars": r.input_chars,
                "output_chars": r.output_chars,
                "tokens_used": r.tokens_used,
                "latency_ms": r.latency_ms,
                "status": r.status,
                "block_reason": r.block_reason,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


# ── Software Update ────────────────────────────────────────────────────────────

import subprocess as _subprocess
import os as _os
import shutil as _shutil
from pathlib import Path as _Path

@router.get("/update/status")
async def update_status(_=Depends(get_current_user)):
    """Return current git commit info and whether origin/main is ahead."""
    try:
        repo = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
        def _git(*args):
            return _subprocess.check_output(["git"] + list(args), cwd=repo, stderr=_subprocess.STDOUT).decode().strip()

        # Fetch silently so we can compare
        try:
            _subprocess.check_output(["git", "fetch", "origin", "main"], cwd=repo, stderr=_subprocess.STDOUT, timeout=15)
        except Exception:
            pass

        current_hash   = _git("rev-parse", "HEAD")[:8]
        current_msg    = _git("log", "-1", "--pretty=%s")
        current_date   = _git("log", "-1", "--pretty=%ci")
        remote_hash    = _git("rev-parse", "origin/main")[:8]
        behind_count   = int(_git("rev-list", "--count", "HEAD..origin/main") or "0")
        recent_commits = _git("log", "origin/main", "--oneline", "-10")

        return {
            "current_hash":    current_hash,
            "current_message": current_msg,
            "current_date":    current_date,
            "remote_hash":     remote_hash,
            "behind_count":    behind_count,
            "update_available": behind_count > 0,
            "recent_commits":  recent_commits,
        }
    except Exception as exc:
        return {"error": str(exc), "update_available": False}


def _repo_root() -> _Path:
    return _Path(__file__).parent.parent.parent.parent


def _venv_pip() -> str:
    pip = _repo_root() / "venv" / "bin" / "pip"
    return str(pip) if pip.exists() else "pip3"


def _run(cmd, cwd=None, timeout=120) -> tuple[bool, str]:
    """Run a command, return (ok, combined_output)."""
    try:
        r = _subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except _subprocess.TimeoutExpired:
        return False, f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except Exception as exc:
        return False, str(exc)


@router.post("/update/pull")
async def pull_update(_=Depends(get_current_user)):
    """Full local-runner update: git pull → pip install → write frontend .env.local."""
    repo = _repo_root()
    steps = []

    # 1 — git pull
    ok, out = _run(["git", "pull", "origin", "main"], cwd=repo, timeout=60)
    steps.append({"step": "git pull", "ok": ok, "output": out})
    already_current = "Already up to date" in out

    # 2 — pip install (pick up any new requirements)
    req = repo / "backend" / "requirements.txt"
    if req.exists():
        ok2, out2 = _run([_venv_pip(), "install", "-q", "-r", str(req)], timeout=300)
        steps.append({"step": "pip install", "ok": ok2, "output": out2 or "All packages up to date"})
    else:
        steps.append({"step": "pip install", "ok": True, "output": "requirements.txt not found — skipped"})

    # 3 — npm install (pick up any new frontend packages)
    fe_dir = repo / "frontend"
    if (fe_dir / "package.json").exists() and _shutil.which("npm"):
        ok3, out3 = _run(["npm", "install", "--prefer-offline"], cwd=fe_dir, timeout=180)
        steps.append({"step": "npm install", "ok": ok3, "output": out3 or "All packages up to date"})
    else:
        steps.append({"step": "npm install", "ok": True, "output": "npm not found or no package.json — skipped"})

    # 4 — ensure frontend/.env.local exists (AADSTS900144 guard)
    fe_env = fe_dir / ".env.local"
    if not fe_env.exists():
        try:
            fe_env.write_text(
                "REACT_APP_API_URL=http://localhost:8000/api/v1\n"
                "REACT_APP_AZURE_CLIENT_ID=2978ef0b-865f-40bc-b7eb-507b6e258ae9\n"
                "REACT_APP_AZURE_TENANT_ID=5e9623cc-7e4c-4408-8b5d-e15ea58e9528\n"
                "REACT_APP_REDIRECT_URI=http://localhost:3000\n"
                "REACT_APP_BACKEND_CLIENT_ID=4972190d-8a6c-4e0e-a326-aee1ca281bf3\n"
            )
            steps.append({"step": "frontend/.env.local", "ok": True, "output": "Created (was missing)"})
        except Exception as exc:
            steps.append({"step": "frontend/.env.local", "ok": False, "output": str(exc)})
    else:
        steps.append({"step": "frontend/.env.local", "ok": True, "output": "Already exists"})

    overall_ok = all(s["ok"] for s in steps)
    combined = "\n".join(f"[{s['step']}]\n{s['output']}" for s in steps)
    return {
        "success":          overall_ok,
        "output":           combined,
        "already_current":  already_current,
        "restart_required": ok and not already_current,
        "steps":            steps,
    }


@router.post("/update/setup-local")
async def setup_local_env(_=Depends(get_current_user)):
    """One-time local environment setup: venv auto-activate + gvm-start in ~/.bashrc."""
    home = _Path.home()
    bashrc = home / ".bashrc"
    added = []

    def _append_if_missing(marker: str, block: str):
        content = bashrc.read_text(errors="replace") if bashrc.exists() else ""
        if marker not in content:
            with bashrc.open("a") as f:
                f.write(f"\n{block}\n")
            added.append(marker)

    # Auto-activate venv
    venv_activate = _repo_root() / "venv" / "bin" / "activate"
    _append_if_missing(
        "# Owlet venv",
        f"# Owlet venv — auto-activate\n"
        f"if [ -f \"{venv_activate}\" ]; then\n"
        f"    source \"{venv_activate}\"\n"
        f"fi",
    )

    # Auto-start GVM daemon (OpenVAS)
    _append_if_missing(
        "# Owlet GVM auto-start",
        "# Owlet GVM auto-start (OpenVAS)\n"
        "if command -v gvmd &>/dev/null && ! pgrep -x gvmd > /dev/null 2>&1; then\n"
        "    sudo gvm-start > /dev/null 2>&1\n"
        "fi",
    )

    # Weekly NVT feed update via cron (every Sunday 2am)
    try:
        import crontab as _ct  # type: ignore
        pass  # crontab module present — use it
    except ImportError:
        _ct = None

    cron_marker = "gvm-feed-update"
    try:
        import subprocess as _sp2
        cron_out = _sp2.run(["crontab", "-l"], capture_output=True, text=True)
        existing_cron = cron_out.stdout if cron_out.returncode == 0 else ""
        if cron_marker not in existing_cron:
            new_cron = existing_cron.rstrip("\n") + "\n# Owlet — weekly OpenVAS NVT feed update\n0 2 * * 0 sudo gvm-feed-update > /dev/null 2>&1\n"
            _sp2.run(["crontab", "-"], input=new_cron, text=True, capture_output=True)
            added.append("gvm-feed-update cron (weekly Sunday 2am)")
    except Exception:
        pass  # crontab not available — skip silently

    if added:
        msg = f"Added to ~/.bashrc: {', '.join(added)}. Open a new terminal or run: source ~/.bashrc"
    else:
        msg = "~/.bashrc already configured — nothing to add."

    return {"success": True, "output": msg, "added": added}
