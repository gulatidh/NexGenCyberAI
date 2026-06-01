"""Phase 7B — proactive buddy triggers.

Wires platform events (new Critical finding, connector error, new
Critical risk, etc.) to catalog buddies so they run without being
asked. Each fired trigger runs the buddy in a background task and
posts the result to the relevant scan blackboard (when scoped to a
scan) or — eventually — a tenant-wide notification feed.

Default triggers seeded on first start:

  - finding.critical → appsec_advisor (output: risk_drafts)
  - finding.high     → vuln_commander (output: finding_triage)
  - risk.critical    → partner_advisor (output: prose)
  - connector.error  → iam_posture_advisor (output: risk_drafts)

Operators add / remove / disable triggers in the AI Buddies admin page.

Hooks call `fire_event(db, kind, payload)` which iterates the enabled
triggers for that kind, evaluates each one's threshold against the
payload, and schedules the matching buddies to run in the background.

Cron entry: a weekly "Buddy roundup" job (registered via the shared
mission scheduler) iterates a curated set of buddies and produces a
one-paragraph synopsis each, aggregated into a Dashboard tile.
"""
from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from api.models.models import AIAgent, BuddyTrigger

logger = logging.getLogger(__name__)


DEFAULT_TRIGGERS: List[Dict[str, Any]] = [
    # Critical findings → AppSec Advisor (drafts risks)
    {"agent_key": "appsec_advisor",     "event_kind": "finding.critical", "threshold": {"severity": "critical"}},
    # High findings → Vuln Commander (triages)
    {"agent_key": "vuln_commander",     "event_kind": "finding.high",     "threshold": {"severity": "high"}},
    # New Critical risk → Partner Advisor (executive read)
    {"agent_key": "partner_advisor",    "event_kind": "risk.critical",    "threshold": {"risk_level": "critical"}},
    # Connector error → IAM Posture Advisor (identity infra often manifests this way)
    {"agent_key": "iam_posture_advisor","event_kind": "connector.error",  "threshold": {}},
]


def seed_default_triggers(db: Session) -> int:
    """Seed the default trigger rows once. Skips any that already exist.

    Also cleans up triggers that point at agent_keys no longer in the
    catalog (e.g. when our defaults were renamed during development)."""
    # ── Cleanup: drop stale triggers pointing at missing buddies ───────
    try:
        valid_keys = {k for (k,) in db.query(AIAgent.key).all()}
        stale = db.query(BuddyTrigger).filter(~BuddyTrigger.agent_key.in_(valid_keys)).all()
        if stale:
            for s in stale:
                db.delete(s)
            db.commit()
            logger.info("Removed %d stale buddy triggers pointing at non-existent keys", len(stale))
    except Exception:
        logger.exception("stale buddy-trigger cleanup failed (non-fatal)")

    written = 0
    for spec in DEFAULT_TRIGGERS:
        existing = (
            db.query(BuddyTrigger)
            .filter(
                BuddyTrigger.agent_key == spec["agent_key"],
                BuddyTrigger.event_kind == spec["event_kind"],
            )
            .first()
        )
        if existing:
            continue
        # Only seed if the buddy actually exists in the catalog.
        if not db.query(AIAgent.id).filter(AIAgent.key == spec["agent_key"]).first():
            logger.info("Skipping trigger seed — buddy '%s' not in catalog", spec["agent_key"])
            continue
        db.add(BuddyTrigger(
            agent_key=spec["agent_key"],
            event_kind=spec["event_kind"],
            threshold_json=spec["threshold"],
            enabled=True,
        ))
        written += 1
    if written:
        db.commit()
        logger.info("Seeded %d default buddy triggers", written)
    return written


def _matches_threshold(threshold: Dict[str, Any], payload: Dict[str, Any]) -> bool:
    """Return True if every key in `threshold` matches the value in `payload`
    (case-insensitive string comparison). Empty threshold = always matches."""
    if not threshold:
        return True
    for k, v in threshold.items():
        pv = payload.get(k)
        if str(pv or "").lower() != str(v or "").lower():
            return False
    return True


def fire_event(
    *,
    event_kind: str,
    payload: Dict[str, Any],
    client_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    findings_for_prompt: Optional[List[Dict[str, Any]]] = None,
) -> int:
    """Run the matching enabled triggers for this event. Opens its own
    short-lived DB session (caller may be in another scope). Returns the
    number of buddies queued."""
    from db.database import SessionLocal
    bg_db = SessionLocal()
    try:
        triggers = (
            bg_db.query(BuddyTrigger)
            .filter(BuddyTrigger.event_kind == event_kind, BuddyTrigger.enabled == True)
            .all()
        )
        queued = 0
        for t in triggers:
            if not _matches_threshold(t.threshold_json or {}, payload):
                continue
            agent = bg_db.query(AIAgent).filter(AIAgent.key == t.agent_key, AIAgent.is_enabled == True).first()
            if not agent:
                continue
            try:
                _run_triggered_buddy(
                    bg_db, agent=agent, client_id=client_id, scan_id=scan_id,
                    payload=payload, findings_for_prompt=findings_for_prompt,
                )
                t.last_fired_at = datetime.now(timezone.utc)
                t.last_status = "ok"
                t.last_error = None
                queued += 1
            except Exception as exc:
                logger.exception("buddy trigger run failed: %s", t.id)
                t.last_status = "error"
                t.last_error = f"{type(exc).__name__}: {exc}"[:1000]
            bg_db.flush()
        bg_db.commit()
        return queued
    finally:
        bg_db.close()


def _run_triggered_buddy(
    db: Session,
    *,
    agent: AIAgent,
    client_id: Optional[str],
    scan_id: Optional[str],
    payload: Dict[str, Any],
    findings_for_prompt: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Synchronous wrapper that runs the agent inline (we're already in a
    background task scope). Persists AgentRun + blackboard entry.

    Kept minimal — this is the proactive path, not the rich on-demand
    path. Uses the buddy's default system prompt + a brief description
    of the triggering event."""
    from core.ai_providers import get_llm
    from langchain_core.messages import HumanMessage, SystemMessage
    from api.models.models import AgentRun, AgentType
    from services.agent_artifacts import VALID_KINDS, prompt_suffix, parse_response
    from services.blackboard import is_enabled as bb_enabled, post as bb_post

    output_kind = (agent.output_kind or "prose").lower()
    if output_kind not in VALID_KINDS:
        output_kind = "prose"

    system_prompt = agent.system_prompt or f"You are the {agent.name}."
    if agent.signature_opening:
        system_prompt += f"\n\nBegin your response with: \"{agent.signature_opening.strip()}\""
    if output_kind != "prose":
        system_prompt += prompt_suffix(output_kind, agent.output_schema_json)

    lines = [
        f"## Trigger event: {payload.get('_event_kind') or 'unknown'}",
        f"You're being woken up because the platform observed an event you're configured to respond to. Produce your standard output for this event.",
    ]
    if payload:
        lines.append("\n## Event payload")
        for k, v in payload.items():
            if k.startswith("_"):
                continue
            lines.append(f"- {k}: {v}")
    if findings_for_prompt:
        lines.append("\n## Related findings")
        for f in findings_for_prompt[:10]:
            lines.append(f"- [{f.get('severity')}] {f.get('title')} on `{f.get('resource') or 'n/a'}`")
    instruction = "\n".join(lines)

    try:
        llm = get_llm(
            provider=agent.provider, model=agent.model,
            temperature=float(agent.temperature or 0.1),
            max_tokens=int(agent.max_tokens or 2048),
        )
        result = asyncio.run(llm.ainvoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=instruction),
        ]))
    except Exception as exc:
        logger.warning("triggered buddy LLM call failed: %s", exc)
        return

    text = result.content if hasattr(result, "content") else str(result)
    if isinstance(text, list):
        text = "\n".join(str(p) for p in text)

    artifacts: List[Dict[str, Any]] = []
    if output_kind != "prose":
        parsed = parse_response(output_kind, text)
        if parsed.get("artifacts"):
            artifacts = parsed["artifacts"]
            if parsed.get("summary"):
                text = parsed["summary"]

    ar = AgentRun(
        client_id=client_id,
        scan_id=scan_id,
        agent_type=AgentType.ORCHESTRATOR,
        status="completed",
        input_data={
            "catalog": True,
            "agent_name": agent.name,
            "agent_key": agent.key,
            "domain": agent.domain,
            "group": agent.group_key,
            "trigger_event": payload.get("_event_kind"),
            "trigger_payload": {k: v for k, v in payload.items() if not k.startswith("_")},
        },
        output_data={
            "summary": text,
            "agent_name": agent.name,
            "agent_key": agent.key,
            "domain": agent.domain,
            "output_kind": output_kind,
            "artifacts": [
                {**a, "applied": False, "applied_entity_id": None, "applied_entity_kind": None}
                for a in artifacts
            ],
            "proactive": True,
        },
        tokens_used=int((getattr(result, "usage_metadata", None) or {}).get("total_tokens") or 0),
    )
    ar.completed_at = datetime.now(timezone.utc)
    db.add(ar)
    db.flush()

    if scan_id:
        try:
            if bb_enabled(db):
                bb_post(db, scan_id=scan_id, agent_run_id=ar.id,
                        agent_name=agent.name, agent_key=agent.key,
                        summary_text=text)
        except Exception:
            logger.exception("blackboard post for triggered buddy failed")


# ── Weekly roundup ───────────────────────────────────────────────────────────


# Buddies that participate in the weekly roundup. Each produces one
# paragraph; the aggregated result lands on the Dashboard.
ROUNDUP_AGENT_KEYS = ["partner_advisor", "appsec_advisor", "soc_strategist", "grc_advisor"]


def weekly_roundup_job() -> None:
    """APScheduler entry-point. Iterates a small curated set of buddies,
    asks each for a one-paragraph 'what changed in your domain this week'
    synopsis, and stores the aggregated result on a singleton row of the
    KnowledgeFile 'buddy_roundup' for the Dashboard to pick up."""
    from db.database import SessionLocal
    from api.models.models import KnowledgeFile
    import json
    bg_db = SessionLocal()
    try:
        out: Dict[str, Any] = {"generated_at": datetime.now(timezone.utc).isoformat(), "entries": []}
        for key in ROUNDUP_AGENT_KEYS:
            agent = bg_db.query(AIAgent).filter(AIAgent.key == key, AIAgent.is_enabled == True).first()
            if not agent:
                continue
            try:
                _run_triggered_buddy(
                    bg_db, agent=agent, client_id=None, scan_id=None,
                    payload={"_event_kind": "weekly.roundup", "window": "last 7 days"},
                )
                # _run_triggered_buddy already wrote an AgentRun; we don't
                # re-fetch the prose here. The roundup tile will pull recent
                # AgentRuns with input_data.trigger_event = 'weekly.roundup'.
                out["entries"].append({"agent_key": key, "ok": True})
            except Exception as exc:
                logger.exception("weekly roundup buddy %s failed", key)
                out["entries"].append({"agent_key": key, "ok": False, "error": str(exc)[:200]})

        # Store / refresh the singleton roundup record so the Dashboard
        # can query it cheaply.
        existing = bg_db.query(KnowledgeFile).filter(KnowledgeFile.category == "buddy_roundup").first()
        if existing:
            existing.description = json.dumps(out)
            existing.metadata_ = out
        else:
            bg_db.add(KnowledgeFile(
                name="Weekly Buddy Roundup",
                category="buddy_roundup",
                description=json.dumps(out),
                version=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                size_kb=1,
                used_by=[],
                metadata_=out,
            ))
        bg_db.commit()
    finally:
        bg_db.close()


def start_weekly_roundup() -> None:
    """Register the weekly cron on the shared mission scheduler."""
    try:
        from services.mission_scheduler import get_scheduler
        from apscheduler.triggers.cron import CronTrigger
        sched = get_scheduler()
        if not sched:
            logger.info("weekly roundup not registered — scheduler unavailable")
            return
        sched.add_job(
            weekly_roundup_job,
            trigger=CronTrigger.from_crontab("0 7 * * 1"),  # Mondays 07:00 UTC
            id="buddy.weekly_roundup",
            replace_existing=True,
        )
        logger.info("weekly buddy roundup registered (Mondays 07:00 UTC)")
    except Exception as exc:
        logger.warning("weekly roundup registration failed: %s", exc)
