"""Current user profile endpoint."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from core.security import get_current_user
from db.database import get_db
from core.authz import get_user_grants, is_admin_anywhere, is_editor_anywhere

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me/")
async def get_me(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return current user identity and access flags."""
    email = (user.get("email") or user.get("preferred_username") or "").lower()
    grants = get_user_grants(db, email) if email else []
    admin_anywhere = is_admin_anywhere(grants)
    editor_anywhere = is_editor_anywhere(grants)
    return {
        "user_id": user.get("sub") or user.get("oid") or "",
        "email": email,
        "display_name": user.get("name") or "",
        "is_admin": admin_anywhere,
        "is_admin_anywhere": admin_anywhere,
        "is_editor_anywhere": editor_anywhere,
    }
