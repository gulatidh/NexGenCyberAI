"""Outbound email — SMTP/Office365 settings, test, and report send.

- GET  /email/config/  : current config (password never echoed)
- PATCH /email/config/ : admin-only upsert of SMTP settings
- POST /email/test/    : admin-only test send to verify the relay
- POST /email/send/    : send a report email (recipient/cc/subject/body + optional attachment)
"""
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.security import get_current_user
from core.authz import require_role, require_editor_anywhere, _user_email
from db.database import get_db
from api.models.models import AccessRole
from services.email_settings import get_config_safe, update_config, PROVIDER_PRESETS
from services.email_sender import send_email, EmailError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/email", tags=["email"])


class EmailConfigUpdate(BaseModel):
    """All fields optional. For smtp_password: send a value to set, "" to
    clear, or omit to leave unchanged."""
    enabled: Optional[bool] = None
    provider: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_security: Optional[str] = None
    from_address: Optional[str] = None
    from_name: Optional[str] = None


class Attachment(BaseModel):
    filename: str
    content_base64: str
    mime: Optional[str] = "application/octet-stream"


class TestEmailRequest(BaseModel):
    to: str


class SendEmailRequest(BaseModel):
    to: List[str] | str
    cc: Optional[List[str] | str] = None
    subject: str
    body_html: Optional[str] = None
    body_text: Optional[str] = None
    attachments: Optional[List[Attachment]] = None


@router.get("/config/")
async def get_email_config(db: Session = Depends(get_db), _=Depends(get_current_user)):
    cfg = get_config_safe(db)
    cfg["provider_presets"] = PROVIDER_PRESETS
    return cfg


@router.patch("/config/")
async def update_email_config(
    payload: EmailConfigUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_role(AccessRole.ADMIN)),
):
    """Admin-only. Persist SMTP/Office365 settings."""
    update_config(db, payload.model_dump(exclude_unset=True), updated_by=_user_email(user))
    return get_config_safe(db)


@router.post("/test/")
async def test_email(
    payload: TestEmailRequest,
    db: Session = Depends(get_db),
    user=Depends(require_role(AccessRole.ADMIN)),
):
    """Admin-only. Send a small test message to verify the relay works."""
    try:
        result = send_email(
            db,
            to=payload.to,
            subject="NexGenCyberAI — SMTP test email",
            body_html=(
                "<p>This is a test email from <b>NexGenCyberAI</b>.</p>"
                "<p>If you received this, your outbound email (SMTP) configuration is working.</p>"
            ),
            body_text="This is a test email from NexGenCyberAI. Your SMTP configuration is working.",
        )
        return {"success": True, **result}
    except EmailError as exc:
        return {"success": False, "error": str(exc)}


@router.post("/send/")
async def send_report_email(
    payload: SendEmailRequest,
    db: Session = Depends(get_db),
    user=Depends(require_editor_anywhere),
):
    """Send a report email. Available to any editor (analysts) — they supply
    recipient(s), subject, body, and an optional attachment built client-side."""
    try:
        atts = [a.model_dump() for a in (payload.attachments or [])]
        result = send_email(
            db,
            to=payload.to,
            cc=payload.cc,
            subject=payload.subject,
            body_html=payload.body_html,
            body_text=payload.body_text,
            attachments=atts,
        )
        logger.info("Report email sent by %s", _user_email(user))
        return {"success": True, **result}
    except EmailError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
