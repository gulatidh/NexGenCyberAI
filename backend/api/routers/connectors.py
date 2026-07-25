"""Connector management endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
import json
from api.models.models import Connector, ConnectorStatus, Project
from api.schemas.schemas import ConnectorCreate, ConnectorUpdate, ConnectorResponse
from db.database import get_db
from core.security import get_current_user
from core.encryption import encrypt, decrypt
from connectors.factory import get_connector
from connectors.sync import sync_connector_assets_bg

router = APIRouter(prefix="/clients/{client_id}/connectors", tags=["connectors"])


@router.get("/", response_model=List[ConnectorResponse])
async def list_connectors(
    client_id: str,
    project_id: str = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(Connector).filter(Connector.client_id == client_id)
    if project_id:
        q = q.filter(Connector.project_id == project_id)
    return q.all()


@router.post("/", response_model=ConnectorResponse, status_code=201)
async def create_connector(
    client_id: str,
    payload: ConnectorCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    project = db.query(Project).filter(Project.id == payload.project_id, Project.client_id == client_id).first()
    if not project:
        raise HTTPException(status_code=400, detail="project_id is required and must belong to this client")
    enc = encrypt(json.dumps(payload.credentials))
    connector = Connector(
        client_id=client_id,
        project_id=payload.project_id,
        name=payload.name,
        connector_type=payload.connector_type,
        credentials_enc=enc,
        config=payload.config or {},
    )
    db.add(connector)
    db.commit()
    db.refresh(connector)
    background_tasks.add_task(sync_connector_assets_bg, connector.id)
    return connector


@router.get("/health")
def connector_health(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return health summary per connector: last scan time, status, finding count."""
    from api.models.models import Scan

    connectors = db.query(Connector).filter(
        Connector.client_id == client_id,
    ).all()

    results = []
    for c in connectors:
        last_scan = (
            db.query(Scan)
            .filter(Scan.client_id == client_id, Scan.connector_id == c.id)
            .order_by(Scan.created_at.desc())
            .first()
        )
        results.append({
            "id": c.id,
            "name": c.name,
            "connector_type": c.connector_type,
            "status": c.status,
            "last_scan_at": last_scan.completed_at if last_scan else None,
            "last_scan_status": last_scan.status if last_scan else None,
            "last_scan_finding_count": (last_scan.summary or {}).get("total", 0) if last_scan else 0,
        })
    return results


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector_detail(client_id: str, connector_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    c = db.query(Connector).filter(Connector.id == connector_id, Connector.client_id == client_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")
    return c


@router.post("/{connector_id}/test")
async def test_connector(
    client_id: str,
    connector_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    c = db.query(Connector).filter(Connector.id == connector_id, Connector.client_id == client_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")
    creds = json.loads(decrypt(c.credentials_enc))
    connector = get_connector(c.connector_type, creds, c.config or {})
    result = await connector.test_connection()
    # Update status
    c.status = ConnectorStatus.ACTIVE if result.success else ConnectorStatus.ERROR
    c.error_message = None if result.success else result.message
    db.commit()
    if result.success:
        background_tasks.add_task(sync_connector_assets_bg, c.id)
    return {"success": result.success, "message": result.message, "details": result.details}


@router.patch("/{connector_id}", response_model=ConnectorResponse)
async def update_connector(
    client_id: str,
    connector_id: str,
    payload: ConnectorUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    c = db.query(Connector).filter(Connector.id == connector_id, Connector.client_id == client_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")
    if payload.name:
        c.name = payload.name
    if payload.project_id:
        project = db.query(Project).filter(Project.id == payload.project_id, Project.client_id == client_id).first()
        if not project:
            raise HTTPException(status_code=400, detail="project_id must belong to this client")
        c.project_id = payload.project_id
    if payload.credentials:
        c.credentials_enc = encrypt(json.dumps(payload.credentials))
    if payload.config:
        c.config = payload.config
    if payload.status:
        c.status = payload.status
    db.commit()
    db.refresh(c)
    return c


@router.delete("/{connector_id}", status_code=204)
async def delete_connector(client_id: str, connector_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    c = db.query(Connector).filter(Connector.id == connector_id, Connector.client_id == client_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")
    db.delete(c)
    db.commit()
