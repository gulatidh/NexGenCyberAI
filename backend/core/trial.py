"""Trial user management and limit enforcement.

Trial accounts are created automatically on first login. Limits:
  - 1 client
  - 3 scans total
  - Operational AI agents only (group_key == "operational")
  - Read-only access to AI settings, connectors, agent instructions

NexGenAdmin role users bypass all trial restrictions.
"""
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any


TRIAL_DAYS = 3
TRIAL_MAX_CLIENTS = 1
TRIAL_MAX_SCANS = 3
TRIAL_ALLOWED_AGENT_GROUP = "operational"


def is_admin(user: Dict[str, Any]) -> bool:
    return "NexGenAdmin" in (user.get("roles") or [])


def get_or_create_trial(db: Session, user: Dict[str, Any]) -> "TrialUser":  # type: ignore[name-defined]
    from api.models.models import TrialUser
    user_id = user.get("sub") or user.get("oid") or ""
    email = user.get("email") or user.get("preferred_username") or user.get("upn") or ""
    display_name = user.get("name") or email

    trial = db.query(TrialUser).filter(TrialUser.user_id == user_id).first()
    if not trial:
        trial = TrialUser(
            user_id=user_id,
            email=email,
            display_name=display_name,
            trial_expires_at=datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS),
        )
        db.add(trial)
        db.commit()
        db.refresh(trial)
    return trial


def trial_status(trial: "TrialUser") -> Dict[str, Any]:  # type: ignore[name-defined]
    now = datetime.now(timezone.utc)
    expires = trial.trial_expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    active = not trial.is_upgraded and now < expires
    days_left = max(0, (expires - now).days) if active else 0
    return {
        "is_trial": not trial.is_upgraded,
        "is_active": active,
        "trial_started_at": trial.trial_started_at.isoformat(),
        "trial_expires_at": expires.isoformat(),
        "days_left": days_left,
        "max_clients": TRIAL_MAX_CLIENTS,
        "max_scans": TRIAL_MAX_SCANS,
        "allowed_agent_group": TRIAL_ALLOWED_AGENT_GROUP,
        "read_only_configs": active,
    }


def require_trial_active(trial: "TrialUser") -> None:  # type: ignore[name-defined]
    if trial.is_upgraded:
        return
    now = datetime.now(timezone.utc)
    expires = trial.trial_expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now >= expires:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Your 3-day trial has expired. Please upgrade to continue.",
        )


def check_client_limit(db: Session, trial: "TrialUser") -> None:  # type: ignore[name-defined]
    if trial.is_upgraded:
        return
    require_trial_active(trial)
    from api.models.models import Client
    count = db.query(Client).filter(Client.deleted_at.is_(None)).count()
    if count >= TRIAL_MAX_CLIENTS:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Trial plan allows {TRIAL_MAX_CLIENTS} client. Upgrade to add more.",
        )


def check_scan_limit(db: Session, trial: "TrialUser", client_id: str) -> None:  # type: ignore[name-defined]
    if trial.is_upgraded:
        return
    require_trial_active(trial)
    from api.models.models import Scan, ScanStatus
    count = (
        db.query(Scan)
        .filter(Scan.client_id == client_id, Scan.status != ScanStatus.CANCELLED)
        .count()
    )
    if count >= TRIAL_MAX_SCANS:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Trial plan allows {TRIAL_MAX_SCANS} scans. Upgrade to run more.",
        )


def check_agent_access(trial: "TrialUser", agent_group: str) -> None:  # type: ignore[name-defined]
    if trial.is_upgraded:
        return
    require_trial_active(trial)
    if agent_group != TRIAL_ALLOWED_AGENT_GROUP:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Trial plan includes Operational AI agents only. Upgrade for full agent access.",
        )


def check_write_access(trial: "TrialUser", resource: str = "configuration") -> None:  # type: ignore[name-defined]
    """Block write operations on sensitive config for trial users."""
    if trial.is_upgraded:
        return
    require_trial_active(trial)
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail=f"Trial plan has read-only access to {resource}. Upgrade to make changes.",
    )
