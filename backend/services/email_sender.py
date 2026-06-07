"""SMTP email sender.

Stateless helper used by the email router. Resolves the tenant SMTP config
(services.email_settings.get_resolved) and sends a multipart message with an
HTML body and optional attachments. Supports STARTTLS (e.g. Office 365 on
587), implicit SSL (465), and plain. Synchronous smtplib is fine here — sends
are low-volume, on-demand, and run inside the request worker."""
from __future__ import annotations
import base64
import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session
from services.email_settings import get_resolved

logger = logging.getLogger(__name__)


class EmailError(Exception):
    """Raised when email is not configured or the SMTP send fails."""


def _split_addrs(value) -> List[str]:
    """Accept a list or a comma/semicolon-separated string of addresses."""
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = str(value).replace(";", ",").split(",")
    return [a.strip() for a in items if a and a.strip()]


def build_message(
    cfg: Dict[str, Any],
    *,
    to: List[str],
    subject: str,
    body_html: Optional[str] = None,
    body_text: Optional[str] = None,
    cc: Optional[List[str]] = None,
    attachments: Optional[List[Dict[str, str]]] = None,
) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = formataddr((cfg.get("from_name") or "", cfg["from_address"]))
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject or "(no subject)"
    msg["Message-ID"] = make_msgid()

    text = body_text or "This message contains an HTML body. Please view it in an HTML-capable client."
    msg.set_content(text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    for att in attachments or []:
        raw = att.get("content_base64")
        if not raw:
            continue
        try:
            data = base64.b64decode(raw)
        except Exception:
            continue
        maintype, _, subtype = (att.get("mime") or "application/octet-stream").partition("/")
        msg.add_attachment(
            data,
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=att.get("filename") or "attachment",
        )
    return msg


def _smtp_send(cfg: Dict[str, Any], msg: EmailMessage, recipients: List[str]) -> None:
    host, port, security = cfg["host"], int(cfg["port"]), cfg["security"]
    timeout = 30
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=timeout)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    try:
        server.ehlo()
        if security == "starttls":
            server.starttls()
            server.ehlo()
        if cfg.get("username") and cfg.get("password"):
            server.login(cfg["username"], cfg["password"])
        server.send_message(msg, from_addr=cfg["from_address"], to_addrs=recipients)
    finally:
        try:
            server.quit()
        except Exception:
            pass


def send_email(
    db: Session,
    *,
    to,
    subject: str,
    body_html: Optional[str] = None,
    body_text: Optional[str] = None,
    cc=None,
    attachments: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Resolve config and send. Raises EmailError on misconfig/failure."""
    cfg = get_resolved(db)
    if cfg is None:
        raise EmailError("Email is not configured. Set up SMTP under Settings → Email and enable it.")
    if not cfg.get("from_address"):
        raise EmailError("No 'From' address configured (set From address or SMTP username).")

    to_list = _split_addrs(to)
    cc_list = _split_addrs(cc)
    if not to_list:
        raise EmailError("At least one recipient is required.")

    msg = build_message(
        cfg, to=to_list, subject=subject, body_html=body_html,
        body_text=body_text, cc=cc_list, attachments=attachments,
    )
    recipients = to_list + cc_list
    try:
        _smtp_send(cfg, msg, recipients)
    except smtplib.SMTPAuthenticationError as exc:
        raise EmailError(
            "SMTP authentication failed. For Office 365, ensure SMTP AUTH is enabled "
            f"for the mailbox and use an app password if MFA is on. ({exc.smtp_code})"
        ) from exc
    except smtplib.SMTPException as exc:
        raise EmailError(f"SMTP send failed: {type(exc).__name__}: {exc}") from exc
    except OSError as exc:
        raise EmailError(f"Could not connect to SMTP server {cfg['host']}:{cfg['port']}: {exc}") from exc

    logger.info("Email sent to %s (subject=%r)", recipients, subject)
    return {"ok": True, "recipients": recipients}
