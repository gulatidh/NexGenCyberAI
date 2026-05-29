"""APScheduler integration — load active ScheduledMissions from the DB on
startup and register them as cron jobs. Re-register/unregister when missions
are added, updated, toggled, or deleted via the API.

In-process scheduler. No broker required (unlike Celery). Fine for the
NexGenCyberAI workload — missions fire daily / weekly / monthly, not
sub-second. If we need to scale to multiple workers later, swap this for
APScheduler's database job store or move to Celery Beat.
"""
from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from db.database import SessionLocal
from api.models.models import ScheduledMission
from services.mission_executor import execute_mission

logger = logging.getLogger(__name__)

_scheduler: Optional[AsyncIOScheduler] = None


def _parse_cron(expr: str, tz: str = "UTC") -> CronTrigger:
    """Convert a 5-field cron string ('m h dom mon dow') to a CronTrigger."""
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"Invalid cron expression (need 5 fields): {expr!r}")
    minute, hour, day, month, day_of_week = parts
    return CronTrigger(
        minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week,
        timezone=tz,
    )


def _job_id(mission_id: str) -> str:
    return f"mission:{mission_id}"


async def _run_mission_job(mission_id: str) -> None:
    """APScheduler entry point — open a DB session and dispatch."""
    db = SessionLocal()
    try:
        mission = db.query(ScheduledMission).filter(ScheduledMission.id == mission_id).first()
        if not mission:
            logger.warning("Mission %s no longer exists; skipping run", mission_id)
            return
        if not mission.is_active:
            logger.info("Mission %s is paused; skipping run", mission_id)
            return
        await execute_mission(db, mission, triggered_by="scheduler")
        db.commit()
    except Exception:
        logger.exception("Scheduler job for mission %s crashed", mission_id)
        db.rollback()
    finally:
        db.close()


def start_scheduler() -> None:
    """Idempotent — safe to call from FastAPI startup."""
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        return
    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.start()
    logger.info("Mission scheduler started")
    _load_all_active_missions()


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Mission scheduler stopped")


def _load_all_active_missions() -> None:
    """Read every active ScheduledMission from the DB and register it."""
    db = SessionLocal()
    try:
        for mission in db.query(ScheduledMission).filter(ScheduledMission.is_active.is_(True)).all():
            try:
                _register(mission)
            except Exception:
                logger.exception("Failed to register mission %s on startup", mission.id)
    finally:
        db.close()


def _register(mission: ScheduledMission) -> None:
    if _scheduler is None:
        return
    trigger = _parse_cron(mission.cron_expression, tz=mission.timezone or "UTC")
    _scheduler.add_job(
        _run_mission_job,
        trigger=trigger,
        args=[mission.id],
        id=_job_id(mission.id),
        replace_existing=True,
        misfire_grace_time=60 * 30,  # 30-min grace if the app was down
    )
    job = _scheduler.get_job(_job_id(mission.id))
    if job and job.next_run_time:
        # Persist next_run_at in the caller's session below — this function
        # is called from contexts that may not own a session, so we don't
        # commit here.
        mission.next_run_at = job.next_run_time.astimezone(timezone.utc)


def _unregister(mission_id: str) -> None:
    if _scheduler is None:
        return
    try:
        _scheduler.remove_job(_job_id(mission_id))
    except Exception:
        pass


def reschedule_mission(mission: ScheduledMission) -> None:
    """Called by the API after a mission is created or updated."""
    _unregister(mission.id)
    if mission.is_active:
        _register(mission)


def remove_mission(mission_id: str) -> None:
    """Called by the API after a mission is deleted."""
    _unregister(mission_id)


def next_run_time(mission_id: str) -> Optional[datetime]:
    """Used by the API to surface the next scheduled fire time."""
    if _scheduler is None:
        return None
    job = _scheduler.get_job(_job_id(mission_id))
    if job and job.next_run_time:
        return job.next_run_time.astimezone(timezone.utc)
    return None
