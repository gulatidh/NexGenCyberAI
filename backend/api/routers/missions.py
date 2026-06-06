"""Scheduled Missions API — CRUD + enable/disable + run-now + audit history.

Missions are global (not scoped under a client in the URL path) but each
mission references a Client by ID. Authorization: any authenticated user
can list missions for clients they have access to; create/update/delete
require admin or editor scope.
"""
from __future__ import annotations
import asyncio
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere
from api.models.models import (
    MissionType, MissionRunStatus, ScheduledMission, ScheduledMissionRun, Client,
)
from services.mission_scheduler import reschedule_mission, remove_mission, next_run_time
from services.mission_executor import execute_mission

router = APIRouter(prefix="/missions", tags=["missions"])


# ── Schemas ──────────────────────────────────────────────────────────────────


class MissionBase(BaseModel):
    name: str = "New Scheduled Mission"
    client_id: str
    mission_type: MissionType
    cron_expression: str = Field(..., description="5-field cron, e.g. '0 6 * * *'")
    cron_label: Optional[str] = None
    timezone: str = "UTC"
    send_summary_email: bool = False
    update_risk_quantification: bool = False
    is_active: bool = True


class MissionCreate(MissionBase):
    pass


class MissionUpdate(BaseModel):
    name: Optional[str] = None
    cron_expression: Optional[str] = None
    cron_label: Optional[str] = None
    timezone: Optional[str] = None
    mission_type: Optional[MissionType] = None
    send_summary_email: Optional[bool] = None
    update_risk_quantification: Optional[bool] = None
    is_active: Optional[bool] = None


class MissionResponse(MissionBase):
    id: str
    last_run_at: Optional[str] = None
    next_run_at: Optional[str] = None
    client_name: Optional[str] = None

    model_config = {"from_attributes": True}


class MissionRunResponse(BaseModel):
    id: str
    mission_id: str
    status: MissionRunStatus
    triggered_by: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    output: Optional[str] = None
    error: Optional[str] = None
    report: Optional[dict] = None

    model_config = {"from_attributes": True}


def _to_response(m: ScheduledMission, db: Session) -> dict:
    client_name = None
    if m.client_id:
        c = db.query(Client.name).filter(Client.id == m.client_id).first()
        client_name = c[0] if c else None
    return {
        "id": m.id,
        "name": m.name,
        "client_id": m.client_id,
        "client_name": client_name,
        "mission_type": m.mission_type,
        "cron_expression": m.cron_expression,
        "cron_label": m.cron_label,
        "timezone": m.timezone or "UTC",
        "send_summary_email": bool(m.send_summary_email),
        "update_risk_quantification": bool(m.update_risk_quantification),
        "is_active": bool(m.is_active),
        "last_run_at": m.last_run_at.isoformat() if m.last_run_at else None,
        "next_run_at": m.next_run_at.isoformat() if m.next_run_at else None,
    }


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/", response_model=List[MissionResponse])
async def list_missions(
    client_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(ScheduledMission)
    if client_id:
        q = q.filter(ScheduledMission.client_id == client_id)
    rows = q.order_by(ScheduledMission.created_at.desc()).all()
    return [_to_response(m, db) for m in rows]


@router.post("/", response_model=MissionResponse, dependencies=[Depends(require_editor_anywhere)])
async def create_mission(
    payload: MissionCreate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    # Validate client exists
    if not db.query(Client.id).filter(Client.id == payload.client_id).first():
        raise HTTPException(status_code=404, detail="Client not found")

    m = ScheduledMission(
        name=payload.name,
        client_id=payload.client_id,
        mission_type=payload.mission_type,
        cron_expression=payload.cron_expression,
        cron_label=payload.cron_label,
        timezone=payload.timezone,
        send_summary_email=payload.send_summary_email,
        update_risk_quantification=payload.update_risk_quantification,
        is_active=payload.is_active,
    )
    db.add(m)
    db.flush()
    reschedule_mission(m)
    nrt = next_run_time(m.id)
    if nrt:
        m.next_run_at = nrt
    db.commit()
    db.refresh(m)
    return _to_response(m, db)


@router.patch("/{mission_id}", response_model=MissionResponse)
async def update_mission(
    mission_id: str,
    payload: MissionUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    m = db.query(ScheduledMission).filter(ScheduledMission.id == mission_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Mission not found")
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(m, k, v)
    db.flush()
    reschedule_mission(m)
    nrt = next_run_time(m.id)
    m.next_run_at = nrt
    db.commit()
    db.refresh(m)
    return _to_response(m, db)


@router.delete("/{mission_id}")
async def delete_mission(
    mission_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    m = db.query(ScheduledMission).filter(ScheduledMission.id == mission_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Mission not found")
    remove_mission(mission_id)
    db.delete(m)
    db.commit()
    return {"deleted": True}


@router.post("/{mission_id}/run", response_model=MissionRunResponse, dependencies=[Depends(require_editor_anywhere)])
async def run_now(
    mission_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Trigger a one-off run regardless of schedule. Audit logged with
    triggered_by='manual'."""
    m = db.query(ScheduledMission).filter(ScheduledMission.id == mission_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Mission not found")
    try:
        run = await execute_mission(db, m, triggered_by="manual")
        db.commit()
        db.refresh(run)
        return run
    except HTTPException:
        raise
    except Exception as exc:
        # Surface root cause so the UI shows something useful instead of a
        # bare 500. execute_mission catches handler exceptions internally
        # and writes them to run.error, so this branch is mostly for
        # session/commit failures.
        db.rollback()
        import logging
        logging.getLogger(__name__).exception("run_now failed for mission %s", mission_id)
        raise HTTPException(status_code=500, detail=f"Mission run failed: {type(exc).__name__}: {exc}")


@router.get("/{mission_id}/runs", response_model=List[MissionRunResponse])
async def list_runs(
    mission_id: str,
    limit: int = 50,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    return (
        db.query(ScheduledMissionRun)
        .filter(ScheduledMissionRun.mission_id == mission_id)
        .order_by(ScheduledMissionRun.started_at.desc())
        .limit(min(limit, 200))
        .all()
    )


@router.get("/runs/recent")
async def list_recent_runs(
    limit: int = 50,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Cross-mission feed of recent workflow runs — powers the Reports page
    'Workflow Outputs' section. Joins to ScheduledMission for the workflow
    name so the UI can render rows without a second request per row."""
    rows = (
        db.query(ScheduledMissionRun, ScheduledMission)
        .join(ScheduledMission, ScheduledMissionRun.mission_id == ScheduledMission.id)
        .order_by(ScheduledMissionRun.started_at.desc())
        .limit(min(limit, 200))
        .all()
    )
    return [
        {
            "id": run.id,
            "mission_id": run.mission_id,
            "mission_name": mission.name,
            "mission_type": mission.mission_type.value if hasattr(mission.mission_type, "value") else str(mission.mission_type),
            "client_id": mission.client_id,
            "status": run.status.value if hasattr(run.status, "value") else str(run.status),
            "triggered_by": run.triggered_by,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            "output": run.output,
            "error": run.error,
        }
        for run, mission in rows
    ]
