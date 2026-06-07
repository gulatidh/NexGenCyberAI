"""Outbound-email (SMTP) settings service.

Mirrors services.ai_settings: a single-row `email_settings` table holds the
tenant-wide SMTP configuration. The SMTP password is stored encrypted; the
UI never receives the cleartext back — only a `smtp_password_configured`
boolean. The sender (services.email_sender) calls `get_resolved()` to obtain
the full config including the decrypted password at send time.
"""
from __future__ import annotations
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from api.models.models import EmailSettings
from core.encryption import encrypt, decrypt

# Non-secret, directly-editable fields.
_PLAIN_FIELDS = (
    "provider", "smtp_host", "smtp_port", "smtp_username",
    "smtp_security", "from_address", "from_name",
)
_BOOL_FIELDS = ("enabled",)

# Sensible per-provider presets the UI can apply client-side; kept here too so
# the test/send paths can fall back if host/port are blank for a known provider.
PROVIDER_PRESETS = {
    "office365": {"smtp_host": "smtp.office365.com", "smtp_port": 587, "smtp_security": "starttls"},
    "gmail":     {"smtp_host": "smtp.gmail.com",     "smtp_port": 587, "smtp_security": "starttls"},
    "smtp":      {},
}


def _load_row(db: Session) -> Optional[EmailSettings]:
    return db.query(EmailSettings).first()


def get_config_safe(db: Session) -> Dict[str, Any]:
    """Config for the UI. Never echoes the SMTP password — exposes only a
    `smtp_password_configured` boolean."""
    row = _load_row(db)
    out: Dict[str, Any] = {
        "enabled": bool(row.enabled) if row else False,
        "provider": (row.provider if row else None) or "office365",
        "smtp_host": (row.smtp_host if row else None),
        "smtp_port": (row.smtp_port if row else None) or 587,
        "smtp_username": (row.smtp_username if row else None),
        "smtp_security": (row.smtp_security if row else None) or "starttls",
        "from_address": (row.from_address if row else None),
        "from_name": (row.from_name if row else None) or "NexGenCyberAI Reports",
        "smtp_password_configured": bool(getattr(row, "smtp_password_enc", None)) if row else False,
        "updated_at": (row.updated_at.isoformat() if row and row.updated_at else None),
        "updated_by": (row.updated_by if row else None),
    }
    return out


def get_resolved(db: Session) -> Optional[Dict[str, Any]]:
    """Full config (including decrypted password) for the sender. Returns None
    if email isn't configured/enabled enough to send."""
    row = _load_row(db)
    if row is None or not row.enabled:
        return None
    host = row.smtp_host or PROVIDER_PRESETS.get(row.provider or "", {}).get("smtp_host")
    if not host:
        return None
    pwd = None
    if row.smtp_password_enc:
        try:
            pwd = decrypt(row.smtp_password_enc)
        except Exception:
            pwd = None
    return {
        "host": host,
        "port": row.smtp_port or PROVIDER_PRESETS.get(row.provider or "", {}).get("smtp_port", 587),
        "username": row.smtp_username or None,
        "password": pwd,
        "security": (row.smtp_security or "starttls").lower(),
        "from_address": row.from_address or row.smtp_username,
        "from_name": row.from_name or "NexGenCyberAI Reports",
    }


def update_config(db: Session, payload: Dict[str, Any], updated_by: Optional[str] = None) -> EmailSettings:
    """Upsert the single-row email_settings record.

    For the password: send a new value to set it, "" to clear, or omit to
    leave unchanged (same contract as AISettings secrets)."""
    row = _load_row(db)
    if row is None:
        row = EmailSettings()
        db.add(row)

    for name in _PLAIN_FIELDS:
        if name in payload and payload[name] is not None:
            val = payload[name]
            if name == "smtp_port":
                try:
                    val = int(val)
                except (TypeError, ValueError):
                    continue
            setattr(row, name, val if val != "" else None)

    for name in _BOOL_FIELDS:
        if name in payload and payload[name] is not None:
            setattr(row, name, bool(payload[name]))

    if "smtp_password" in payload:
        v = payload["smtp_password"]
        if v == "":
            row.smtp_password_enc = None
        elif v is not None:
            row.smtp_password_enc = encrypt(v)

    if updated_by:
        row.updated_by = updated_by

    db.commit()
    db.refresh(row)
    return row
