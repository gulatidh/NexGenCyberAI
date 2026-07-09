"""Current user profile and trial status endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from db.database import get_db
from core.security import get_current_user
from core.trial import get_trial, create_trial, trial_status, is_admin, TRIAL_DAYS, TRIAL_MAX_CLIENTS, TRIAL_MAX_SCANS

router = APIRouter(prefix="/users", tags=["users"])

_NO_TRIAL = {
    "is_trial": False,
    "is_active": False,
    "days_left": None,
    "max_clients": None,
    "max_scans": None,
    "allowed_agent_group": None,
    "read_only_configs": False,
}


@router.get("/me/")
async def get_me(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Return current user identity and trial status."""
    admin = is_admin(user)
    trial = None if admin else get_trial(db, user)
    return {
        "user_id": user.get("sub") or user.get("oid") or "",
        "email": user.get("email") or user.get("preferred_username") or "",
        "display_name": user.get("name") or "",
        "is_admin": admin,
        "trial": trial_status(trial) if trial else _NO_TRIAL,
    }


@router.post("/trial/start/")
async def start_trial(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Activate a 3-day trial. Called when the user clicks Start Free Trial on the landing page.
    Idempotent — returns the existing trial if already activated."""
    if is_admin(user):
        return {"message": "Admin accounts do not use trials.", "trial": _NO_TRIAL}
    trial = create_trial(db, user)
    return {"message": "Trial activated.", "trial": trial_status(trial)}
