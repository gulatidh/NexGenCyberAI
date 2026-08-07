"""Dispatch webhook events to configured endpoints."""
import json
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import httpx

logger = logging.getLogger(__name__)


async def dispatch_event(event_type: str, payload: Dict[str, Any], client_id: Optional[str] = None):
    """Fire all matching active webhooks for this event. Called as a BackgroundTask."""
    from db.database import SessionLocal
    from api.models.models import WebhookConfig, WebhookDelivery

    db = SessionLocal()
    try:
        q = db.query(WebhookConfig).filter(WebhookConfig.is_active == True)
        webhooks = q.all()

        body = json.dumps({"event": event_type, "timestamp": datetime.now(timezone.utc).isoformat(), "data": payload})

        for wh in webhooks:
            # Check event filter
            wh_events = wh.events or []
            if wh_events and event_type not in wh_events and not any(
                event_type.startswith(e.rstrip("*")) for e in wh_events if e.endswith("*")
            ):
                continue
            # Client filter
            if wh.client_id and client_id and wh.client_id != client_id:
                continue

            delivery = WebhookDelivery(
                webhook_id=wh.id,
                event_type=event_type,
                payload={"event": event_type, "data": payload},
                status="pending",
            )
            db.add(delivery)
            db.flush()

            headers = {"Content-Type": "application/json", "X-Owlet-Event": event_type}
            if wh.secret:
                sig = hmac.new(wh.secret.encode(), body.encode(), hashlib.sha256).hexdigest()
                headers["X-Owlet-Signature"] = f"sha256={sig}"

            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(wh.url, content=body, headers=headers)
                delivery.status = "success" if resp.status_code < 400 else "failed"
                delivery.response_status = resp.status_code
            except Exception as exc:
                delivery.status = "failed"
                delivery.error = str(exc)
                logger.warning("Webhook delivery failed for %s: %s", wh.url, exc)

            delivery.delivered_at = datetime.now(timezone.utc)
            db.commit()

    finally:
        db.close()
