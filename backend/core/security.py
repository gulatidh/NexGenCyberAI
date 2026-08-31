"""
NexGenCyberAI - Security Utilities
JWT validation against Azure Entra ID OIDC tokens.

Multi-tenant support: tokens from ANY work/school Azure AD tenant are accepted.
The issuer is validated dynamically against the tid claim in the token, which
prevents token confusion attacks while allowing external users (e.g. accenture.com)
to authenticate. Access is gated — only users with an explicit UserAccess grant
(or listed in INITIAL_ADMIN_EMAILS for first-run bootstrap) can reach the API.
"""
import jwt
from jwt import PyJWKClient
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from core.config import get_settings
from db.database import get_db

settings = get_settings()
bearer_scheme = HTTPBearer()

# Use the common (tenant-independent) JWKS endpoint so signing keys from any
# Azure AD tenant are resolvable. The PyJWKClient caches keys automatically.
_COMMON_JWKS_URI = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
_jwks_client: Optional[PyJWKClient] = None


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        uri = settings.AZURE_JWKS_URI or _COMMON_JWKS_URI
        _jwks_client = PyJWKClient(uri)
    return _jwks_client


def decode_azure_token(token: str) -> Dict[str, Any]:
    """Validate an Entra ID access token and return the claims.

    Issuer validation uses the tid claim embedded in the token itself so that
    tokens from any Azure AD tenant (accenture.com, contoso.com, etc.) are
    accepted, while still preventing token confusion across tenants.
    """
    try:
        # Decode header only (no verification) to extract tid before full decode
        unverified = jwt.decode(token, options={"verify_signature": False})
        tid = unverified.get("tid", "")
        if not tid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing tenant claim")

        client = _get_jwks_client()
        signing_key = client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            # Azure AD issues tokens with aud = CLIENT_ID (v2) or api://CLIENT_ID (v1); accept both
            audience=[
                settings.AZURE_CLIENT_ID,
                f"api://{settings.AZURE_CLIENT_ID}",
            ],
            # Validate issuer dynamically from the token's own tid claim
            issuer=[
                f"https://login.microsoftonline.com/{tid}/v2.0",
                f"https://sts.windows.net/{tid}/",
            ],
            options={"verify_exp": True},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {exc}")


def _is_guest_jwt(raw: str) -> bool:
    """Quick header-only check — avoids calling Azure JWKS for guest tokens."""
    try:
        import jwt as _jwt
        unverified = _jwt.decode(raw, options={"verify_signature": False})
        return bool(unverified.get("guest"))
    except Exception:
        return False


def decode_guest_token(raw: str) -> Dict[str, Any]:
    """Validate a guest JWT issued by guest_tokens.py and return the claims."""
    import jwt as _jwt
    secret = settings.SECRET_KEY + ":guest"
    try:
        payload = _jwt.decode(raw, secret, algorithms=["HS256"])
        if not payload.get("guest"):
            raise HTTPException(status_code=401, detail="Not a guest token")
        return payload
    except _jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Guest session expired — request a new link")
    except _jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid guest token: {exc}")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Validate JWT and enforce that the caller has at least one access grant.

    Supports two token types:
      1. Azure AD JWT   — validated via JWKS; requires a UserAccess grant row.
      2. Guest JWT      — validated with HMAC secret; maps to a GuestToken row.

    Guest users get a user dict with guest=True, client_id, project_id set.
    All downstream route handlers that allow guests must NOT call require_admin
    or require_editor_anywhere — those already block guests because guest dicts
    have no 'roles', 'upn', or UserAccess row.
    """
    raw = credentials.credentials

    # ── Guest JWT path ──────────────────────────────────────────────────────────
    if _is_guest_jwt(raw):
        claims = decode_guest_token(raw)
        # Re-validate the DB row (in case token was revoked after JWT was issued)
        from api.models.models import GuestToken
        from datetime import datetime, timezone
        row = db.query(GuestToken).filter(GuestToken.id == claims.get("token_id")).first()
        if not row or row.is_revoked:
            raise HTTPException(status_code=403, detail="Guest link has been revoked")
        exp = row.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Guest link has expired")
        return {
            "guest": True,
            "sub": f"guest:{row.id}",
            "email": f"guest:{row.id}",
            "preferred_username": f"guest:{row.label}",
            "client_id": row.client_id,
            "project_id": row.project_id,
            "label": row.label,
        }

    # ── Azure AD JWT path ───────────────────────────────────────────────────────
    user = decode_azure_token(raw)

    email = (
        user.get("upn")
        or user.get("preferred_username")
        or user.get("email")
        or user.get("unique_name", "")
    ).strip().lower()

    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not identify user email from token")

    initial_admins = {
        e.strip().lower()
        for e in (settings.INITIAL_ADMIN_EMAILS or "").split(",")
        if e.strip()
    }
    if email in initial_admins:
        return user

    from api.models.models import UserAccess
    has_grant = db.query(UserAccess).filter(UserAccess.email == email).first()
    if not has_grant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access not granted. Contact your administrator to request access.",
        )

    return user


async def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    roles = user.get("roles", [])
    if "NexGenAdmin" not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


async def require_not_guest(user: Dict = Depends(get_current_user)) -> Dict:
    """Blocks guest-JWT callers from write / configure endpoints."""
    if user.get("guest"):
        raise HTTPException(status_code=403, detail="Guest access is read-only")
    return user
