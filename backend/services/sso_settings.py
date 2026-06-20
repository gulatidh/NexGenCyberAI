"""SSO / Entra ID settings service.

Mirrors services.email_settings: a single-row `sso_settings` table holds the
tenant-wide Azure AD configuration. The client secret is stored encrypted;
the UI never receives the cleartext — only a `client_secret_configured` bool.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from api.models.models import SsoSettings
from core.encryption import encrypt, decrypt


def _load_row(db: Session) -> Optional[SsoSettings]:
    return db.query(SsoSettings).first()


def get_config_safe(db: Session) -> Dict[str, Any]:
    row = _load_row(db)
    tenant_id = row.tenant_id if row else None
    return {
        "enabled": bool(row.enabled) if row else False,
        "tenant_id": tenant_id,
        "client_id": row.client_id if row else None,
        "client_secret_configured": bool(getattr(row, "client_secret_enc", None)) if row else False,
        "redirect_uri": row.redirect_uri if row else None,
        "authority": row.authority if row else (
            f"https://login.microsoftonline.com/{tenant_id}" if tenant_id else None
        ),
        "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
        "updated_by": row.updated_by if row else None,
    }


def update_config(db: Session, data: Dict[str, Any], updated_by: str = "") -> None:
    row = _load_row(db)
    if row is None:
        row = SsoSettings(id=__import__("uuid").uuid4().hex)
        db.add(row)

    plain = ("enabled", "tenant_id", "client_id", "redirect_uri", "authority")
    for field in plain:
        if field in data:
            setattr(row, field, data[field])

    if "client_secret" in data:
        secret = data["client_secret"]
        if secret == "":
            row.client_secret_enc = None
        elif secret:
            row.client_secret_enc = encrypt(secret)

    # Auto-compute authority from tenant_id if not explicitly provided
    if "tenant_id" in data and data["tenant_id"] and "authority" not in data:
        row.authority = f"https://login.microsoftonline.com/{data['tenant_id']}"

    row.updated_at = datetime.now(timezone.utc)
    row.updated_by = updated_by
    db.commit()


def get_client_secret(db: Session) -> Optional[str]:
    row = _load_row(db)
    if not row or not row.client_secret_enc:
        return None
    return decrypt(row.client_secret_enc)
