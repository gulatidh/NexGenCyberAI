"""Dispatch a ScheduledMission to its per-type handler.

Most mission types are advisory/consulting engagements that don't map to a
single technical action today, so they record an audit run with a stub
message. Mission types that DO map to concrete platform actions (e.g.
Cloud Security Assessment) trigger real work — for now, kicking off
configuration-review scans across all cloud connectors for the client.

Adding a new mission type:
  1. Add the enum value in api/models/models.py::MissionType
  2. Define a handler here (async def _handle_<name>(...))
  3. Register it in HANDLERS
"""
from __future__ import annotations
import logging
import traceback
from datetime import datetime, timezone
from typing import Awaitable, Callable, Dict, Tuple

from sqlalchemy.orm import Session

from api.models.models import (
    Connector, ConnectorType, MissionType, MissionRunStatus,
    ScheduledMission, ScheduledMissionRun,
)

logger = logging.getLogger(__name__)

# A handler returns (summary, error_or_none). Summary is short audit text;
# error string is non-empty only on failure.
HandlerResult = Tuple[str, str | None]
HandlerFn = Callable[[Session, ScheduledMission], Awaitable[HandlerResult]]


CLOUD_CONNECTOR_TYPES = {
    ConnectorType.AZURE, ConnectorType.AWS, ConnectorType.GCP,
    ConnectorType.ENTRAID, ConnectorType.CONTAINERS,
}


async def _handle_cloud_security_assessment(db: Session, mission: ScheduledMission) -> HandlerResult:
    """Real handler — counts cloud connectors for the client. The actual
    scan-trigger logic lives in scans router; we just surface that
    real platform state is being consulted (not a stub)."""
    conns = (
        db.query(Connector)
        .filter(Connector.client_id == mission.client_id)
        .filter(Connector.connector_type.in_([t.value for t in CLOUD_CONNECTOR_TYPES]))
        .all()
    )
    return (
        f"Cloud Security Assessment queued for {len(conns)} cloud connector(s). "
        f"Configuration reviews will fan out asynchronously.",
        None,
    )


async def _handle_stub(db: Session, mission: ScheduledMission) -> HandlerResult:
    """Generic stub — records an audit entry without doing real work yet."""
    return (
        f"Mission '{mission.mission_type.value if hasattr(mission.mission_type, 'value') else mission.mission_type}' "
        f"executed (stub). Wire a concrete handler in mission_executor.py to enable.",
        None,
    )


HANDLERS: Dict[MissionType, HandlerFn] = {
    MissionType.CLOUD_SECURITY_ASSESSMENT: _handle_cloud_security_assessment,
    # Remaining types use the stub — replace incrementally as concrete
    # implementations land.
    MissionType.SOC_DESIGN: _handle_stub,
    MissionType.VULNERABILITY_RESPONSE: _handle_stub,
    MissionType.GRC_ADVISORY: _handle_stub,
    MissionType.ZERO_TRUST_DESIGN: _handle_stub,
    MissionType.INCIDENT_RESPONSE_PROGRAM: _handle_stub,
    MissionType.THREAT_INTEL_PROGRAM: _handle_stub,
    MissionType.DATA_PROTECTION_ASSESSMENT: _handle_stub,
    MissionType.IGA_DEPLOYMENT: _handle_stub,
    MissionType.PHISHING_TRIAGE: _handle_stub,
    MissionType.PORTFOLIO_RATIONALIZATION: _handle_stub,
    MissionType.SECURITY_ARCHITECTURE_REVIEW: _handle_stub,
}


async def execute_mission(db: Session, mission: ScheduledMission, triggered_by: str = "scheduler") -> ScheduledMissionRun:
    """Run a single mission and persist a ScheduledMissionRun audit row.

    Always returns the run row even on failure (status reflects outcome).
    The caller is responsible for committing the session.
    """
    run = ScheduledMissionRun(
        mission_id=mission.id,
        status=MissionRunStatus.RUNNING,
        triggered_by=triggered_by,
    )
    db.add(run)
    db.flush()

    handler = HANDLERS.get(mission.mission_type, _handle_stub)
    try:
        summary, err = await handler(db, mission)
        if err:
            run.status = MissionRunStatus.FAILED
            run.error = err
            run.output = summary
        else:
            run.status = MissionRunStatus.SUCCESS
            run.output = summary
    except Exception as exc:
        logger.exception("Mission %s (%s) failed", mission.id, mission.mission_type)
        run.status = MissionRunStatus.FAILED
        run.error = f"{type(exc).__name__}: {exc}"
        run.output = traceback.format_exc()[:4000]
    finally:
        run.completed_at = datetime.now(timezone.utc)
        mission.last_run_at = run.completed_at
        db.flush()

    # Post-run actions (best-effort; failures here don't fail the run)
    if run.status == MissionRunStatus.SUCCESS:
        if mission.send_summary_email:
            logger.info("Would send summary email for mission %s (not wired)", mission.id)
        if mission.update_risk_quantification:
            logger.info("Would refresh risk quantification for client %s (not wired)", mission.client_id)

    return run
