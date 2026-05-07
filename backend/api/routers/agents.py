"""AI Agent execution endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone
from api.models.models import AgentRun, AgentType, Scan, Finding
from api.schemas.schemas import AgentRunRequest, AgentRunResponse
from db.database import get_db
from core.security import get_current_user
from agents.orchestrator.orchestrator import AgentOrchestrator

router = APIRouter(prefix="/clients/{client_id}/agents", tags=["agents"])
_orchestrator = AgentOrchestrator()


@router.post("/run/", response_model=AgentRunResponse)
async def run_agent(
    client_id: str,
    payload: AgentRunRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    # Load findings if scan_id provided
    findings = []
    if payload.scan_id:
        raw = db.query(Finding).filter(Finding.scan_id == payload.scan_id).all()
        findings = [
            {
                "title": f.title,
                "description": f.description or "",
                "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                "resource_id": f.resource_id or "",
                "control_id": f.control_id or "",
                "cve_id": f.cve_id or "",
                "cvss_score": f.cvss_score or 0,
            }
            for f in raw
        ]

    from ...api.models.models import Client
    client = db.query(Client).filter(Client.id == client_id).first()
    client_name = client.name if client else "Unknown"

    agent_run_db = AgentRun(
        client_id=client_id,
        agent_type=payload.agent_type,
        scan_id=payload.scan_id,
        status="running",
        input_data=payload.input_data or {},
    )
    db.add(agent_run_db)
    db.commit()
    db.refresh(agent_run_db)

    try:
        result = await _orchestrator.run_single_agent(
            payload.agent_type.value,
            findings,
            client_name,
        )
        agent_run_db.output_data = result
        agent_run_db.status = "completed"
    except Exception as exc:
        agent_run_db.status = "failed"
        agent_run_db.error_message = str(exc)
        result = {"error": str(exc)}

    agent_run_db.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(agent_run_db)
    return agent_run_db


@router.get("/runs/", response_model=List[AgentRunResponse])
async def list_agent_runs(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(AgentRun).filter(AgentRun.client_id == client_id).order_by(AgentRun.started_at.desc()).limit(20).all()


@router.get("/runs/{run_id}", response_model=AgentRunResponse)
async def get_agent_run(client_id: str, run_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.client_id == client_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Agent run not found")
    return run
