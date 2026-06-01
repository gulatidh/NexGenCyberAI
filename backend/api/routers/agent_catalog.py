"""AI Agent catalog API — browse for any authenticated user, CRUD for admins.

Admin check follows the same DB-grant pattern as admin.py — anyone with
admin role at any scope (global, client, or project) can create / modify /
delete agents. Built-in agents (`is_builtin=True`) cannot be deleted via
the API; admins can edit them. New agents are always `is_builtin=False`.
"""
from __future__ import annotations
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import get_db
from core.security import get_current_user
from api.models.models import AIAgent
from core.authz import get_user_grants, is_admin_anywhere

router = APIRouter(prefix="/agents/catalog", tags=["agent_catalog"])


# ── Auth helpers ─────────────────────────────────────────────────────────────


def _user_email(user: dict) -> str:
    for k in ("preferred_username", "upn", "email"):
        v = user.get(k)
        if v:
            return v.lower()
    return ""


def _require_admin(user: dict = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    email = _user_email(user)
    if not email:
        raise HTTPException(status_code=401, detail="Could not identify user")
    grants = get_user_grants(db, email)
    if not is_admin_anywhere(grants):
        raise HTTPException(status_code=403, detail="Admin role required to modify the agent catalog")
    return user


# ── Schemas ──────────────────────────────────────────────────────────────────


class AgentBase(BaseModel):
    key: str
    name: str
    group_key: str
    group_label: str
    description: Optional[str] = None
    objective: Optional[str] = None
    domain: Optional[str] = None
    system_prompt: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4096
    tools_enabled: List[str] = []
    knowledge_file_ids: List[str] = []
    is_enabled: bool = True


class AgentCreate(AgentBase):
    pass


class AgentUpdate(BaseModel):
    name: Optional[str] = None
    group_key: Optional[str] = None
    group_label: Optional[str] = None
    description: Optional[str] = None
    objective: Optional[str] = None
    domain: Optional[str] = None
    system_prompt: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    tools_enabled: Optional[List[str]] = None
    knowledge_file_ids: Optional[List[str]] = None
    is_enabled: Optional[bool] = None


class AgentResponse(AgentBase):
    id: str
    is_builtin: bool
    legacy_orchestrator: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    updated_by: Optional[str] = None

    model_config = {"from_attributes": True}


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/")
async def list_agents(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return agents grouped by group_key, sorted by builtin-first then name."""
    rows = db.query(AIAgent).order_by(AIAgent.group_key, AIAgent.is_builtin.desc(), AIAgent.name).all()
    grouped: Dict[str, Dict[str, Any]] = {}
    for a in rows:
        if a.group_key not in grouped:
            grouped[a.group_key] = {"key": a.group_key, "label": a.group_label, "agents": []}
        grouped[a.group_key]["agents"].append(AgentResponse.model_validate(a).model_dump(mode="json"))
    return {"groups": list(grouped.values())}


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    a = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
    return a


@router.post("/", response_model=AgentResponse)
async def create_agent(
    payload: AgentCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(_require_admin),
):
    if db.query(AIAgent.id).filter(AIAgent.key == payload.key).first():
        raise HTTPException(status_code=409, detail=f"Agent key '{payload.key}' already exists")
    a = AIAgent(
        **payload.model_dump(),
        is_builtin=False,
        created_by=_user_email(user),
        updated_by=_user_email(user),
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


@router.patch("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: str,
    payload: AgentUpdate,
    db: Session = Depends(get_db),
    user: dict = Depends(_require_admin),
):
    a = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(a, k, v)
    a.updated_by = _user_email(user)
    db.commit()
    db.refresh(a)
    return a


@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    _: dict = Depends(_require_admin),
):
    a = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
    if a.is_builtin:
        raise HTTPException(status_code=409, detail="Built-in agents cannot be deleted. Disable them via the `is_enabled` toggle instead.")
    db.delete(a)
    db.commit()
    return {"deleted": True}


class AgentRunRequest(BaseModel):
    prompt: Optional[str] = None  # user instruction; default is "Provide your standard briefing."
    client_id: Optional[str] = None  # optional context anchor
    scan_id: Optional[str] = None  # if set, agent reads findings + verdict and run is attached to scan


class AgentRunResponse(BaseModel):
    agent_id: str
    agent_name: str
    output: str
    provider: str
    model: Optional[str] = None
    tokens_used: int = 0
    duration_ms: int = 0
    run_id: Optional[str] = None       # persisted AgentRun id when scan_id was provided
    scan_id: Optional[str] = None


@router.post("/{agent_id}/run", response_model=AgentRunResponse)
async def run_agent(
    agent_id: str,
    payload: AgentRunRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Execute a catalog agent. If `scan_id` is provided, the agent reads
    that scan's findings + verdict, treats them as context, and the run is
    persisted as an AgentRun tied to the scan so it shows up on the
    Assessment detail page just like operational agents do.

    Legacy operational agents (`legacy_orchestrator=True`) are not run via
    this path — they have their own routers at
    `/clients/{client_id}/agents/run/`.
    """
    import time
    from datetime import datetime, timezone
    from core.ai_providers import get_llm
    from langchain_core.messages import HumanMessage, SystemMessage
    from api.models.models import AgentRun, AgentType, Scan, Finding, Client

    a = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
    if not a.is_enabled:
        raise HTTPException(status_code=409, detail="Agent is disabled. Enable it before running.")
    if a.legacy_orchestrator:
        raise HTTPException(
            status_code=409,
            detail="Legacy operational agents must be run via /clients/{client_id}/agents/run/ with a client context.",
        )

    # ── Build scan context if scan_id is supplied ───────────────────────────
    scan: Optional[Scan] = None
    client: Optional[Client] = None
    findings_for_prompt: List[dict] = []
    context_block = ""
    effective_client_id = payload.client_id

    if payload.scan_id:
        scan = db.query(Scan).filter(Scan.id == payload.scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        effective_client_id = scan.client_id
        client = db.query(Client).filter(Client.id == scan.client_id).first()
        rows = (
            db.query(Finding)
            .filter(Finding.scan_id == scan.id)
            .order_by(Finding.cvss_score.desc())
            .limit(80)
            .all()
        )
        for f in rows:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            findings_for_prompt.append({
                "title": f.title or "",
                "severity": sev,
                "resource": f.resource_id or "",
                "cve": f.cve_id or "",
                "cvss": float(f.cvss_score) if f.cvss_score else None,
                "control": f.control_id or "",
            })
        sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings_for_prompt:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        verdict_obj = scan.ai_verdict or {}
        verdict_summary = verdict_obj.get("verdict") if isinstance(verdict_obj, dict) else None

        lines = [
            "## Scan context",
            f"- Client: {client.name if client else 'Unknown'}",
            f"- Scan ID: {scan.id}",
            f"- Scan type: {scan.scan_type.value if hasattr(scan.scan_type, 'value') else scan.scan_type}",
            f"- Findings: {len(findings_for_prompt)} ({sev_counts})",
        ]
        if verdict_summary:
            lines.append(f"- Previous AI verdict (one-liner): {verdict_summary}")
        lines.append("")
        lines.append("## Top findings (severity-ordered, capped at 30)")
        for f in findings_for_prompt[:30]:
            extra = []
            if f["cve"]:
                extra.append(f["cve"])
            if f["cvss"] is not None:
                extra.append(f"CVSS {f['cvss']:.1f}")
            if f["control"]:
                extra.append(f["control"])
            tail = f" [{' · '.join(extra)}]" if extra else ""
            lines.append(f"- [{f['severity']}] {f['title']} on `{f['resource'] or 'n/a'}`{tail}")
        context_block = "\n".join(lines)

    # ── Build the instruction ───────────────────────────────────────────────
    base_instruction = (payload.prompt or "").strip()
    if not base_instruction:
        if scan:
            base_instruction = (
                f"Analyse the findings above from the {a.domain or a.name} perspective. "
                "Identify the most material issues, map them to your domain's controls, "
                "and recommend concrete next steps."
            )
        else:
            base_instruction = (
                f"Provide your standard briefing on {a.domain or a.name}. "
                "Be concise and senior-level. Cite framework controls where relevant."
            )

    formatting_guidance = (
        "\n\nFormatting rules: Respond in well-structured markdown using level-3 "
        "headers (### ...) for sections, bulleted lists for items, and bold for "
        "key terms. Third-person executive tone. No greetings, no 'I will', "
        "no questions to the user, no offers like 'If you want, I can also'."
    )

    instruction = (context_block + "\n\n" + base_instruction + formatting_guidance) if context_block \
        else base_instruction + formatting_guidance

    # ── Retrieval-augmented context — prepend top-k semantically similar
    # learnings from prior engagements (Phase 5C). When semantic learning is
    # disabled or no learnings exist yet, this is a no-op.
    try:
        from services.learning_memory import find_relevant, render_learnings_block
        learnings = find_relevant(
            db,
            query_text=(context_block + "\n\n" + base_instruction)[:4000],
            client_id=effective_client_id,
            agent_key=a.key,
            domain=a.domain,
            k=5,
        )
        if learnings:
            instruction = render_learnings_block(learnings) + "\n" + instruction
    except Exception:
        logger.exception("learning retrieval failed (continuing without)")

    # ── Blackboard injection (Phase 5D) — peer agents' synopses on the
    # same scan. No-op when scan is None or blackboard is disabled.
    if scan:
        try:
            from services.blackboard import recent_entries as bb_recent, render_blackboard_block, is_enabled as bb_enabled
            if bb_enabled(db):
                entries = bb_recent(db, scan_id=scan.id, k=6)
                bb_block = render_blackboard_block(entries, exclude_agent_key=a.key)
                if bb_block:
                    instruction = bb_block + "\n" + instruction
        except Exception:
            logger.exception("blackboard read failed (continuing without)")

    # ── LLM call ────────────────────────────────────────────────────────────
    started = time.perf_counter()
    try:
        llm = get_llm(
            provider=a.provider,
            model=a.model,
            temperature=float(a.temperature or 0.1),
            max_tokens=int(a.max_tokens or 4096),
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"LLM unavailable: {exc}")

    messages = [
        SystemMessage(content=a.system_prompt or f"You are the {a.name}."),
        HumanMessage(content=instruction),
    ]
    try:
        result = await llm.ainvoke(messages)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Agent invocation failed: {type(exc).__name__}: {exc}")

    duration_ms = int((time.perf_counter() - started) * 1000)
    text = result.content if hasattr(result, "content") else str(result)
    if isinstance(text, list):
        text = "\n".join(str(p) for p in text)
    usage = getattr(result, "usage_metadata", None) or {}
    tokens = int(usage.get("total_tokens") or 0)
    original_output = text

    # ── Self-critique pass (opt-in via AISettings.self_critique_enabled) ──
    critique_meta: Optional[Dict[str, Any]] = None
    try:
        from services.agent_critique import is_enabled as critique_is_enabled, critique as run_critique
        if critique_is_enabled(db):
            cres = await run_critique(llm=llm, instruction=instruction, output=text)
            critique_meta = {
                "decision": cres["decision"],
                "issues": cres["issues"],
                "tokens": cres.get("tokens", 0),
            }
            if cres["decision"] == "revise" and cres["revised_output"]:
                text = cres["revised_output"]
            tokens += int(cres.get("tokens") or 0)
    except Exception as exc:
        # Never let the critique step break the agent run.
        logger.exception("self-critique pass failed (continuing with original output)")
        critique_meta = {"decision": "error", "issues": [str(exc)[:160]], "tokens": 0}

    # ── Persist as AgentRun when we have a scan, so it appears on the
    # Assessment detail page next to operational agent tabs. agent_type is
    # ORCHESTRATOR (existing enum value); the catalog agent's display name +
    # key live in input_data so the UI can label the tab correctly.
    run_id: Optional[str] = None
    if scan:
        ar = AgentRun(
            client_id=effective_client_id,
            scan_id=scan.id,
            agent_type=AgentType.ORCHESTRATOR,
            status="completed",
            input_data={
                "catalog": True,
                "agent_name": a.name,
                "agent_key": a.key,
                "domain": a.domain,
                "group": a.group_key,
                "user_prompt": payload.prompt or "",
            },
            output_data={
                "summary": text,
                "agent_name": a.name,
                "agent_key": a.key,
                "domain": a.domain,
                # When self-critique ran, persist the original alongside the
                # revised version so the UI can show "self-reviewed" and let
                # the user inspect what changed.
                **({"original_summary": original_output, "critique": critique_meta}
                   if critique_meta is not None and original_output != text
                   else ({"critique": critique_meta} if critique_meta is not None else {})),
            },
            tokens_used=tokens,
        )
        ar.completed_at = datetime.now(timezone.utc)
        db.add(ar)
        db.commit()
        db.refresh(ar)
        run_id = ar.id

        # ── Post-run: extract learnings (Phase 5B) and post blackboard
        # summary (Phase 5D). Both are background tasks so the user sees
        # their result immediately; failures don't block the response.
        background_tasks.add_task(
            _post_run_learning_and_blackboard,
            agent_run_id=ar.id,
            scan_id=scan.id,
            client_id=effective_client_id,
            agent_key=a.key,
            agent_name=a.name,
            domain=a.domain,
            output_text=text,
        )

    return AgentRunResponse(
        agent_id=a.id,
        agent_name=a.name,
        output=text,
        provider=a.provider or "default",
        model=a.model,
        tokens_used=tokens,
        duration_ms=duration_ms,
        run_id=run_id,
        scan_id=scan.id if scan else None,
    )


def _post_run_learning_and_blackboard(
    *,
    agent_run_id: str,
    scan_id: str,
    client_id: Optional[str],
    agent_key: Optional[str],
    agent_name: Optional[str],
    domain: Optional[str],
    output_text: str,
) -> None:
    """Background-task target. Opens its own DB session because BackgroundTasks
    fire after the request's session is closed."""
    import asyncio
    from db.database import SessionLocal
    bg_db = SessionLocal()
    try:
        # 5D — write to blackboard first (cheap, no LLM call).
        try:
            from services.blackboard import is_enabled as bb_enabled, post as bb_post
            if bb_enabled(bg_db):
                bb_post(
                    bg_db,
                    scan_id=scan_id,
                    agent_run_id=agent_run_id,
                    agent_name=agent_name,
                    agent_key=agent_key,
                    summary_text=output_text,
                )
        except Exception:
            logger.exception("blackboard post failed for agent_run %s", agent_run_id)

        # 5B — extract learnings (LLM call). Awaited in a fresh event loop.
        try:
            from services.learning_memory import extract_learnings
            asyncio.run(extract_learnings(
                bg_db,
                text=output_text,
                source_kind="agent_run",
                source_id=agent_run_id,
                client_id=client_id,
                agent_key=agent_key,
                domain=domain,
            ))
        except Exception:
            logger.exception("learning extraction failed for agent_run %s", agent_run_id)
    finally:
        bg_db.close()
