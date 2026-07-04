"""Ticket Integration Router — create and sync ServiceNow/Jira tickets from findings and remediation actions."""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.models.models import Connector, ConnectorType, Finding, RemediationAction, TicketSync
from connectors.factory import get_connector
from connectors.saas.servicenow.connector import ServiceNowConnector
from connectors.saas.jira.connector import JiraConnector
from core.encryption import decrypt
from core.security import get_current_user
from db.database import get_db

router = APIRouter(prefix="/clients/{client_id}/tickets", tags=["tickets"])

_TICKET_CONNECTOR_TYPES = {ConnectorType.SERVICENOW, ConnectorType.JIRA}


# ── Request schemas ─────────────────────────────────────────────────────────────

class CreateFromFindingRequest(BaseModel):
    finding_id: str
    connector_id: str
    assignment_group: Optional[str] = None   # ServiceNow
    project_key: Optional[str] = None        # Jira


class CreateFromRemediationRequest(BaseModel):
    remediation_action_id: str
    connector_id: str
    assignment_group: Optional[str] = None   # ServiceNow
    project_key: Optional[str] = None        # Jira


# ── Response schema ─────────────────────────────────────────────────────────────

class TicketSyncResponse(BaseModel):
    id: str
    client_id: str
    connector_type: Optional[str]
    source_type: Optional[str]
    source_id: Optional[str]
    ticket_id: Optional[str]
    ticket_url: Optional[str]
    ticket_status: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _load_connector(client_id: str, connector_id: str, db: Session) -> Connector:
    conn = db.query(Connector).filter(
        Connector.id == connector_id,
        Connector.client_id == client_id,
    ).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    if conn.connector_type not in _TICKET_CONNECTOR_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Connector must be of type servicenow or jira, got {conn.connector_type}",
        )
    return conn


def _decrypt_creds(conn: Connector) -> Dict[str, Any]:
    try:
        return json.loads(decrypt(conn.credentials_enc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt connector credentials: {exc}")


async def _create_sn_ticket(
    creds: Dict[str, Any],
    config: Dict[str, Any],
    title: str,
    description: str,
    severity: str,
    assignment_group: Optional[str],
) -> Dict[str, Any]:
    connector = ServiceNowConnector(credentials=creds, config=config)
    return await connector.create_incident(
        title=title,
        description=description,
        severity=severity,
        assignment_group=assignment_group,
    )


async def _create_jira_ticket(
    creds: Dict[str, Any],
    config: Dict[str, Any],
    title: str,
    description: str,
    severity: str,
    project_key: Optional[str],
) -> Dict[str, Any]:
    connector = JiraConnector(credentials=creds, config=config)
    return await connector.create_issue(
        title=title,
        description=description,
        severity=severity,
        project_key=project_key,
    )


def _severity_from_finding(finding: Finding) -> str:
    if finding.severity:
        v = finding.severity
        return v.value if hasattr(v, "value") else str(v)
    return "medium"


# ── Endpoints ───────────────────────────────────────────────────────────────────

@router.get("/connectors/", response_model=List[Dict])
async def list_ticket_connectors(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List configured ServiceNow/Jira connectors for this client."""
    rows = db.query(Connector).filter(
        Connector.client_id == client_id,
        Connector.connector_type.in_(["servicenow", "jira"]),
    ).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "connector_type": r.connector_type.value if hasattr(r.connector_type, "value") else r.connector_type,
            "status": r.status.value if hasattr(r.status, "value") else r.status,
            "config": r.config or {},
        }
        for r in rows
    ]


@router.post("/create-from-finding/", response_model=TicketSyncResponse)
async def create_ticket_from_finding(
    client_id: str,
    payload: CreateFromFindingRequest,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Create a ServiceNow incident or Jira issue from an existing Finding."""
    finding = db.query(Finding).filter(Finding.id == payload.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    conn = _load_connector(client_id, payload.connector_id, db)
    creds = _decrypt_creds(conn)
    config = conn.config or {}
    severity = _severity_from_finding(finding)
    title = finding.title or "Security Finding"
    description = finding.description or title

    if conn.connector_type == ConnectorType.SERVICENOW:
        result = await _create_sn_ticket(creds, config, title, description, severity, payload.assignment_group)
        ticket_id = result["sys_id"]
        ticket_url = result["url"]
        ticket_status = "new"
    else:
        result = await _create_jira_ticket(
            creds, config, title, description, severity,
            payload.project_key or config.get("project_key"),
        )
        ticket_id = result["key"]
        ticket_url = result["url"]
        ticket_status = "open"

    ctype = conn.connector_type.value if hasattr(conn.connector_type, "value") else str(conn.connector_type)
    sync = TicketSync(
        client_id=client_id,
        connector_type=ctype,
        source_type="finding",
        source_id=payload.finding_id,
        ticket_id=ticket_id,
        ticket_url=ticket_url,
        ticket_status=ticket_status,
    )
    db.add(sync)
    db.commit()
    db.refresh(sync)
    return sync


@router.post("/create-from-remediation/", response_model=TicketSyncResponse)
async def create_ticket_from_remediation(
    client_id: str,
    payload: CreateFromRemediationRequest,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Create a ServiceNow incident or Jira issue from a RemediationAction."""
    action = db.query(RemediationAction).filter(
        RemediationAction.id == payload.remediation_action_id,
        RemediationAction.client_id == client_id,
    ).first()
    if not action:
        raise HTTPException(status_code=404, detail="Remediation action not found")

    conn = _load_connector(client_id, payload.connector_id, db)
    creds = _decrypt_creds(conn)
    config = conn.config or {}

    title = action.title or action.action[:100] if action.action else "Remediation Action"
    description = action.action or title
    # Derive severity from band
    band = action.band or ""
    if "Quick Win" in band:
        severity = "high"
    elif "Near Term" in band:
        severity = "medium"
    else:
        severity = "low"

    if conn.connector_type == ConnectorType.SERVICENOW:
        result = await _create_sn_ticket(creds, config, title, description, severity, payload.assignment_group)
        ticket_id = result["sys_id"]
        ticket_url = result["url"]
        ticket_status = "new"
    else:
        result = await _create_jira_ticket(
            creds, config, title, description, severity,
            payload.project_key or config.get("project_key"),
        )
        ticket_id = result["key"]
        ticket_url = result["url"]
        ticket_status = "open"

    ctype = conn.connector_type.value if hasattr(conn.connector_type, "value") else str(conn.connector_type)
    sync = TicketSync(
        client_id=client_id,
        connector_type=ctype,
        source_type="remediation_action",
        source_id=payload.remediation_action_id,
        ticket_id=ticket_id,
        ticket_url=ticket_url,
        ticket_status=ticket_status,
    )
    db.add(sync)
    db.commit()
    db.refresh(sync)
    return sync


@router.get("/", response_model=List[TicketSyncResponse])
async def list_ticket_syncs(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List all ticket syncs for this client (newest first, max 100)."""
    return (
        db.query(TicketSync)
        .filter(TicketSync.client_id == client_id)
        .order_by(TicketSync.created_at.desc())
        .limit(100)
        .all()
    )


@router.post("/{ticket_sync_id}/sync/", response_model=TicketSyncResponse)
async def sync_ticket_status(
    client_id: str,
    ticket_sync_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Fetch the current status from the ticketing system and update the TicketSync record."""
    sync = db.query(TicketSync).filter(
        TicketSync.id == ticket_sync_id,
        TicketSync.client_id == client_id,
    ).first()
    if not sync:
        raise HTTPException(status_code=404, detail="TicketSync not found")

    # Find any connector of matching type for this client (use the first active one)
    ctype_str = sync.connector_type or ""
    try:
        ctype = ConnectorType(ctype_str)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown connector type: {ctype_str}")

    conn = db.query(Connector).filter(
        Connector.client_id == client_id,
        Connector.connector_type == ctype,
    ).first()
    if not conn:
        raise HTTPException(status_code=404, detail=f"No {ctype_str} connector configured for this client")

    creds = _decrypt_creds(conn)
    config = conn.config or {}

    if ctype == ConnectorType.SERVICENOW:
        sn = ServiceNowConnector(credentials=creds, config=config)
        result = await sn.get_incident_status(sync.ticket_id)
        sync.ticket_status = result.get("state", sync.ticket_status)
    else:
        jira = JiraConnector(credentials=creds, config=config)
        result = await jira.get_issue_status(sync.ticket_id)
        sync.ticket_status = result.get("status", sync.ticket_status)

    sync.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(sync)
    return sync
