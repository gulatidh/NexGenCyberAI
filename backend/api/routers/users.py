"""Current user profile and trial status endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from db.database import get_db
from core.security import get_current_user
from core.trial import get_or_create_trial, trial_status, is_admin, TRIAL_DAYS, TRIAL_MAX_CLIENTS, TRIAL_MAX_SCANS

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me/")
async def get_me(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Return current user identity and trial status."""
    admin = is_admin(user)
    if admin:
        return {
            "user_id": user.get("sub") or user.get("oid") or "",
            "email": user.get("email") or user.get("preferred_username") or "",
            "display_name": user.get("name") or "",
            "is_admin": True,
            "trial": {
                "is_trial": False,
                "is_active": False,
                "days_left": None,
                "max_clients": None,
                "max_scans": None,
                "read_only_configs": False,
            },
        }

    trial = get_or_create_trial(db, user)
    return {
        "user_id": user.get("sub") or user.get("oid") or "",
        "email": user.get("email") or user.get("preferred_username") or "",
        "display_name": user.get("name") or "",
        "is_admin": False,
        "trial": trial_status(trial),
    }
