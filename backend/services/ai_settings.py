"""AI provider settings service.

Resolves the active AI configuration by reading the single-row `ai_settings`
table first, then falling back to env-var values from `core.config.Settings`.

API keys are stored encrypted; consumers (`core.ai_providers.*`) call
`get_resolved_value("openai_api_key")` etc. to get plaintext on demand.
"""
from __future__ import annotations
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from db.database import SessionLocal
from api.models.models import AISettings
from core.config import get_settings
from core.encryption import encrypt, decrypt

# Names that map to env-var Settings attributes.
_PLAIN_FIELDS = {
    "default_provider": "DEFAULT_AI_PROVIDER",
    "default_model": None,  # not in env (provider-specific defaults exist)
    "default_temperature": None,
    "azure_openai_endpoint": "AZURE_OPENAI_ENDPOINT",
    "azure_openai_deployment": "AZURE_OPENAI_DEPLOYMENT",
    "azure_openai_api_version": "AZURE_OPENAI_API_VERSION",
    "aws_bedrock_region": "AWS_BEDROCK_REGION",
    # Phase 5 — learning memory / critique / blackboard config (string fields)
    "embedding_provider": None,
    "embedding_model": None,
}

# Phase 5 boolean toggles. Same plumbing as _PLAIN_FIELDS but cast to bool
# on read/write so the UI gets `true`/`false` and the DB stores 0/1.
_BOOL_FIELDS = {
    "self_critique_enabled",
    "semantic_learning_enabled",
    "blackboard_enabled",
}

# Encrypted-at-rest secret fields. Map: db column → env-var name.
_SECRET_FIELDS = {
    "openai_api_key": "OPENAI_API_KEY",
    "azure_openai_api_key": "AZURE_OPENAI_API_KEY",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "google_api_key": "GOOGLE_API_KEY",
    "aws_bedrock_access_key": "AWS_BEDROCK_ACCESS_KEY",
    "aws_bedrock_secret_key": "AWS_BEDROCK_SECRET_KEY",
}


def _load_row(db: Session) -> Optional[AISettings]:
    return db.query(AISettings).first()


def get_resolved_value(name: str) -> Optional[str]:
    """Return the resolved value for one config field.

    Tries DB row first; on miss, falls back to the matching env-var. Opens
    its own short-lived Session so it's safe to call from anywhere
    (including outside request scope, e.g. agent module init).
    """
    db = SessionLocal()
    try:
        row = _load_row(db)
        if row is not None:
            if name in _SECRET_FIELDS:
                enc = getattr(row, f"{name}_enc", None)
                if enc:
                    try:
                        return decrypt(enc)
                    except Exception:
                        pass  # corrupted ciphertext — fall through to env
            elif name in _PLAIN_FIELDS:
                v = getattr(row, name, None)
                if v not in (None, ""):
                    return v
    finally:
        db.close()

    s = get_settings()
    env_attr = _PLAIN_FIELDS.get(name) if name in _PLAIN_FIELDS else _SECRET_FIELDS.get(name)
    if env_attr:
        v = getattr(s, env_attr, None)
        return v if v else None
    return None


def get_config_safe(db: Session) -> Dict[str, Any]:
    """Return the current config for the UI: plaintext for non-secret fields,
    booleans for secrets indicating whether they are configured (never echo
    the cleartext key back to the client)."""
    row = _load_row(db)
    s = get_settings()
    out: Dict[str, Any] = {}

    for name, env_attr in _PLAIN_FIELDS.items():
        db_val = getattr(row, name, None) if row else None
        env_val = getattr(s, env_attr, None) if env_attr else None
        out[name] = db_val if db_val not in (None, "") else (env_val or None)

    for name, env_attr in _SECRET_FIELDS.items():
        db_set = bool(getattr(row, f"{name}_enc", None)) if row else False
        env_set = bool(getattr(s, env_attr, None))
        out[f"{name}_configured"] = db_set or env_set
        out[f"{name}_source"] = "db" if db_set else ("env" if env_set else "none")

    # Phase 5 toggles — explicit defaults so the UI doesn't see undefined.
    _defaults = {
        "self_critique_enabled": False,
        "semantic_learning_enabled": False,
        "blackboard_enabled": True,
    }
    for name in _BOOL_FIELDS:
        v = getattr(row, name, None) if row else None
        out[name] = bool(v) if v is not None else _defaults[name]

    return out


def update_config(db: Session, payload: Dict[str, Any], updated_by: Optional[str] = None) -> AISettings:
    """Upsert the single-row ai_settings record with provided fields."""
    row = _load_row(db)
    if row is None:
        row = AISettings()
        db.add(row)

    for name in _PLAIN_FIELDS:
        if name in payload and payload[name] is not None:
            setattr(row, name, payload[name] or None)

    for name in _BOOL_FIELDS:
        if name in payload and payload[name] is not None:
            setattr(row, name, bool(payload[name]))

    for name in _SECRET_FIELDS:
        if name in payload:
            v = payload[name]
            if v == "":
                # explicit clear
                setattr(row, f"{name}_enc", None)
            elif v is not None:
                setattr(row, f"{name}_enc", encrypt(v))

    if updated_by:
        row.updated_by = updated_by

    db.commit()
    db.refresh(row)
    return row
