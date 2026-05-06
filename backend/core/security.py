"""
NexGenCyberAI - Security Utilities
JWT validation against Azure Entra ID OIDC tokens.
"""
import httpx
import jwt
from jwt import PyJWKClient
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, Dict, Any
from .config import get_settings

settings = get_settings()
bearer_scheme = HTTPBearer()

_jwks_client: Optional[PyJWKClient] = None


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        uri = settings.AZURE_JWKS_URI or (
            f"https://login.microsoftonline.com/{settings.AZURE_TENANT_ID}"
            f"/discovery/v2.0/keys"
        )
        _jwks_client = PyJWKClient(uri)
    return _jwks_client


def decode_azure_token(token: str) -> Dict[str, Any]:
    """Validate an Entra ID access token and return the claims."""
    try:
        client = _get_jwks_client()
        signing_key = client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.AZURE_CLIENT_ID,
            issuer=[
                f"https://login.microsoftonline.com/{settings.AZURE_TENANT_ID}/v2.0",
                f"https://sts.windows.net/{settings.AZURE_TENANT_ID}/",
            ],
            options={"verify_exp": True},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {exc}")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> Dict[str, Any]:
    return decode_azure_token(credentials.credentials)


async def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    roles = user.get("roles", [])
    if "NexGenAdmin" not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user
