"""Webhook configuration and delivery log endpoints."""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional

from api.models.models import WebhookConfig, WebhookDelivery
from api.schemas.schemas import WebhookCreate, WebhookResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.get("/", response_model=List[WebhookResponse])
async def list_webhooks(
    client_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(WebhookConfig)
    if client_id:
        q = q.filter((WebhookConfig.client_id == client_id) | (WebhookConfig.client_id.is_(None)))
    return q.order_by(WebhookConfig.created_at.desc()).all()


@router.post("/", response_model=WebhookResponse, dependencies=[Depends(require_editor_anywhere)])
async def create_webhook(payload: WebhookCreate, db: Session = Depends(get_db), _=Depends(get_current_user)):
    wh = WebhookConfig(**payload.model_dump())
    db.add(wh)
    db.commit()
    db.refresh(wh)
    return wh


@router.patch("/{webhook_id}", response_model=WebhookResponse, dependencies=[Depends(require_editor_anywhere)])
async def toggle_webhook(webhook_id: str, is_active: bool, db: Session = Depends(get_db), _=Depends(get_current_user)):
    wh = db.query(WebhookConfig).filter(WebhookConfig.id == webhook_id).first()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    wh.is_active = is_active
    db.commit()
    db.refresh(wh)
    return wh


@router.delete("/{webhook_id}", dependencies=[Depends(require_editor_anywhere)])
async def delete_webhook(webhook_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    wh = db.query(WebhookConfig).filter(WebhookConfig.id == webhook_id).first()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    db.delete(wh)
    db.commit()
    return {"deleted": True}


@router.get("/{webhook_id}/deliveries")
async def list_deliveries(webhook_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return (
        db.query(WebhookDelivery)
        .filter(WebhookDelivery.webhook_id == webhook_id)
        .order_by(WebhookDelivery.created_at.desc())
        .limit(50)
        .all()
    )


@router.post("/{webhook_id}/test", dependencies=[Depends(require_editor_anywhere)])
async def test_webhook(webhook_id: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Fire a test event to the webhook URL."""
    wh = db.query(WebhookConfig).filter(WebhookConfig.id == webhook_id).first()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    from services.webhook_dispatcher import dispatch_event
    background_tasks.add_task(dispatch_event, "webhook.test", {"message": "Test event from Monitara"}, wh.client_id)
    return {"queued": True}
