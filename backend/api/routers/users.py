"""Current user profile endpoint."""
from fastapi import APIRouter, Depends
from core.security import get_current_user

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me/")
async def get_me(user: dict = Depends(get_current_user)):
    """Return current user identity."""
    return {
        "user_id": user.get("sub") or user.get("oid") or "",
        "email": user.get("email") or user.get("preferred_username") or "",
        "display_name": user.get("name") or "",
    }
