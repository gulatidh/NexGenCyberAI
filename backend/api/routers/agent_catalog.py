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
from api.models.models import AIAgent, AgentRun, Risk, RiskLevel
from core.authz import get_user_grants, is_admin_anywhere
from services.risk_scoring import clamp_scale, compute_risk_score

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
    # Phase 7A — artifact-producing buddy config. Optional so existing rows
    # with NULL values don't fail Pydantic validation pre-migration.
    output_kind: Optional[str] = "prose"
    output_schema_json: Optional[str] = None
    # Phase 7C — personality
    avatar_url: Optional[str] = None
    signature_opening: Optional[str] = None
    accent_color: Optional[str] = None


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
    output_kind: Optional[str] = None
    output_schema_json: Optional[str] = None
    avatar_url: Optional[str] = None
    signature_opening: Optional[str] = None
    accent_color: Optional[str] = None


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

    # Trial: only operational group agents allowed
    from core.trial import get_trial, check_agent_access, is_admin
    if not is_admin(user):
        _trial = get_trial(db, user)
        check_agent_access(_trial, a.group_key or "")

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

    # Phase 7A — if the buddy declares a non-prose output_kind, append the
    # canonical JSON schema directive so we get back a structured response
    # we can parse into actionable artifacts.
    output_kind = (a.output_kind or "prose").lower().strip()
    from services.agent_artifacts import VALID_KINDS, prompt_suffix as artifact_prompt_suffix, parse_response as parse_artifact_response
    if output_kind not in VALID_KINDS:
        output_kind = "prose"
    system_prompt_full = a.system_prompt or f"You are the {a.name}."
    if a.signature_opening:
        # Phase 7C — the signature is a one-liner the buddy uses to open
        # every response. Reinforces identity across runs.
        system_prompt_full += (
            f"\n\nBegin your response with: \"{a.signature_opening.strip()}\""
        )
    if output_kind != "prose":
        system_prompt_full += artifact_prompt_suffix(output_kind, a.output_schema_json)

    messages = [
        SystemMessage(content=system_prompt_full),
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

    # Phase 7A — parse structured artifacts when the buddy declares a
    # non-prose output_kind. On parse failure, we keep the prose summary
    # and surface a soft error in the meta so the UI can tell the user.
    artifacts: List[Dict[str, Any]] = []
    artifact_errors: List[str] = []
    if output_kind != "prose":
        parsed = parse_artifact_response(output_kind, text)
        artifacts = parsed.get("artifacts") or []
        artifact_errors = parsed.get("errors") or []
        # When structured parsing succeeded, replace the prose body with
        # the model's own `summary` field — it's the executive overview
        # paired with the artifacts.
        if artifacts and parsed.get("summary"):
            text = parsed["summary"]

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
                # Phase 7A — structured artifacts the user can act on via
                # POST /agents/catalog/runs/{run_id}/artifacts/{idx}/apply.
                # Each artifact's `applied` field starts false; the apply
                # endpoint flips it to true and stores the resulting entity
                # id (risk_id / kb_file_id / etc.) so the UI can disable
                # the button + link to the created entity.
                "output_kind": output_kind,
                "artifacts": [
                    {**art, "applied": False, "applied_entity_id": None, "applied_entity_kind": None}
                    for art in artifacts
                ],
                "artifact_errors": artifact_errors,
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


class ArtifactApplyResponse(BaseModel):
    applied: bool
    entity_kind: Optional[str] = None   # 'risk' | 'kb_file' | 'framework_assessment' | 'finding' | 'jira_copy'
    entity_id: Optional[str] = None
    message: Optional[str] = None


def _risk_level_from(sev: str) -> RiskLevel:
    s = (sev or "medium").lower().strip()
    mapping = {
        "critical": RiskLevel.CRITICAL,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
    }
    return mapping.get(s, RiskLevel.MEDIUM)


def _apply_risk_draft(db: Session, run: AgentRun, artifact: Dict[str, Any], user: dict) -> Risk:
    """Create a Risk Register row from a risk_drafts artifact."""
    title = (artifact.get("title") or "(untitled)").strip()[:500]
    sev = (artifact.get("severity") or "medium").lower()
    likelihood = clamp_scale(artifact.get("likelihood"), 5)
    impact = clamp_scale(artifact.get("impact"), 5)
    rationale = (artifact.get("rationale") or "").strip()
    refs = artifact.get("control_refs") or []
    if isinstance(refs, list) and refs:
        rationale = (rationale + "\n\nControl refs: " + ", ".join(str(r) for r in refs)).strip()
    risk = Risk(
        client_id=run.client_id,
        title=title,
        description=rationale,
        risk_level=_risk_level_from(sev),
        likelihood=likelihood,
        impact=impact,
        risk_score=compute_risk_score(likelihood, impact),
        category=(artifact.get("category") or "").strip()[:100] or None,
        owner=user.get("upn") or user.get("preferred_username"),
        status="open",
        mitigation_plan=(artifact.get("mitigation_plan") or "").strip() or None,
        finding_ids=[],
    )
    db.add(risk)
    db.flush()
    return risk


def _apply_runbook(db: Session, run: AgentRun, artifact: Dict[str, Any]) -> Any:
    """Save a runbook artifact as a KnowledgeFile in the 'Buddy Runbooks' category."""
    from api.models.models import KnowledgeFile
    title = (artifact.get("title") or "Untitled runbook").strip()[:255]
    steps_md = []
    for s in (artifact.get("steps") or []):
        if isinstance(s, dict):
            line = f"{s.get('order', '?')}. {s.get('action', '')}"
            if s.get("notes"):
                line += f"\n   _{s['notes']}_"
            steps_md.append(line)
    rollback_md = ""
    rb = artifact.get("rollback_steps") or []
    if rb:
        rollback_md = "\n\n## Rollback\n" + "\n".join(f"- {r}" for r in rb)
    description = (
        f"**Trigger:** {artifact.get('trigger', '—')}\n\n"
        f"**Audience:** {artifact.get('audience', '—')}\n\n"
        f"## Steps\n" + "\n".join(steps_md) + rollback_md
    )
    kf = KnowledgeFile(
        name=title,
        category="buddy_runbooks",
        description=description,
        version="v1.0",
        size_kb=max(1, len(description) // 1024),
        used_by=[],
        metadata_={"source": "buddy_artifact", "agent_run_id": run.id},
    )
    db.add(kf)
    db.flush()
    return kf


def _apply_control_mapping(db: Session, run: AgentRun, artifact: Dict[str, Any]) -> Any:
    """Stash a control-mapping artifact as a note on the latest FrameworkAssessment
    for this client + framework. We don't overwrite the canonical scoring — we
    add to a 'buddy_suggested_mappings' JSON array so the user reviews them
    before they affect the assessment."""
    from api.models.models import FrameworkAssessment, FrameworkType
    framework_str = (artifact.get("framework") or "").lower().strip()
    try:
        fw = FrameworkType(framework_str)
    except ValueError:
        return None
    assessment = (
        db.query(FrameworkAssessment)
        .filter(FrameworkAssessment.client_id == run.client_id, FrameworkAssessment.framework == fw)
        .order_by(FrameworkAssessment.assessed_at.desc())
        .first()
    )
    if assessment is None:
        return None
    bucket = (assessment.gaps or []) if isinstance(assessment.gaps, list) else []
    bucket.append({
        "source": "buddy_artifact",
        "agent_run_id": run.id,
        "control_id": artifact.get("control_id"),
        "evidence": artifact.get("evidence"),
        "status": artifact.get("status"),
        "confidence": artifact.get("confidence"),
    })
    assessment.gaps = bucket
    db.flush()
    return assessment


def _apply_finding_triage(db: Session, run: AgentRun, artifact: Dict[str, Any]) -> Any:
    """Update a finding's status / owner based on the buddy's triage."""
    from api.models.models import Finding
    fid = artifact.get("finding_id")
    if not fid:
        return None
    f = db.query(Finding).filter(Finding.id == fid).first()
    if not f:
        return None
    new_status = (artifact.get("recommended_status") or "").strip()
    if new_status:
        f.status = new_status
    # Owner role doesn't map to a single field; stash it in evidence
    role = (artifact.get("recommended_owner_role") or "").strip()
    if role:
        ev = dict(f.evidence or {})
        ev["buddy_owner_role"] = role
        ev["buddy_rationale"] = artifact.get("rationale", "")
        f.evidence = ev
    db.flush()
    return f


@router.post("/runs/{run_id}/artifacts/{idx}/apply", response_model=ArtifactApplyResponse)
async def apply_artifact(
    run_id: str,
    idx: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """One-click apply for a buddy-produced artifact (Phase 7A).

    Dispatches by `output_kind`:
      risk_drafts      → creates a Risk Register row
      runbook          → saves a KnowledgeFile under 'buddy_runbooks'
      control_mappings → appends to the latest FrameworkAssessment's gaps[]
      finding_triage   → updates the referenced Finding's status / evidence
      jira_drafts      → no-op (frontend handles copy-to-clipboard)

    Idempotent: the artifact's `applied` flag prevents double-apply."""
    run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="AgentRun not found")
    out = dict(run.output_data or {})
    artifacts = list(out.get("artifacts") or [])
    if idx < 0 or idx >= len(artifacts):
        raise HTTPException(status_code=404, detail=f"Artifact index {idx} out of range")
    artifact = dict(artifacts[idx])
    if artifact.get("applied"):
        return ArtifactApplyResponse(
            applied=True,
            entity_kind=artifact.get("applied_entity_kind"),
            entity_id=artifact.get("applied_entity_id"),
            message="Already applied",
        )

    kind = (out.get("output_kind") or "prose").lower()
    entity_kind: Optional[str] = None
    entity_id: Optional[str] = None
    try:
        if kind == "risk_drafts":
            risk = _apply_risk_draft(db, run, artifact, user)
            entity_kind, entity_id = "risk", risk.id
        elif kind == "runbook":
            kf = _apply_runbook(db, run, artifact)
            entity_kind, entity_id = "kb_file", kf.id
        elif kind == "control_mappings":
            a = _apply_control_mapping(db, run, artifact)
            if a is None:
                raise HTTPException(status_code=409, detail="No matching FrameworkAssessment for this client/framework — run a scan against this framework first.")
            entity_kind, entity_id = "framework_assessment", a.id
        elif kind == "finding_triage":
            f = _apply_finding_triage(db, run, artifact)
            if f is None:
                raise HTTPException(status_code=404, detail="Finding not found")
            entity_kind, entity_id = "finding", f.id
        elif kind == "jira_drafts":
            # Frontend handles copy-to-clipboard. We still mark it applied
            # so the button toggles to "copied".
            entity_kind, entity_id = "jira_copy", None
        else:
            raise HTTPException(status_code=400, detail=f"output_kind '{kind}' has no apply handler")
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("artifact apply failed (run=%s idx=%s kind=%s)", run_id, idx, kind)
        raise HTTPException(status_code=500, detail=f"Apply failed: {type(exc).__name__}: {exc}")

    # Mark the artifact applied on the AgentRun row.
    artifact["applied"] = True
    artifact["applied_entity_kind"] = entity_kind
    artifact["applied_entity_id"] = entity_id
    artifacts[idx] = artifact
    out["artifacts"] = artifacts
    run.output_data = out
    # SQLAlchemy doesn't detect in-place dict mutation on JSON columns
    # without flag_modified.
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(run, "output_data")
    db.commit()
    return ArtifactApplyResponse(applied=True, entity_kind=entity_kind, entity_id=entity_id, message="Applied")


@router.get("/{agent_id}/stats")
async def get_agent_stats(
    agent_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Phase 7C — per-buddy usage telemetry. Powers the strip on each
    catalog tile: 'N runs · M artifacts applied · K learnings stored'."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func, cast, String
    from api.models.models import AgentRun, MissionLearning
    a = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")

    last_30 = datetime.now(timezone.utc) - timedelta(days=30)
    # Use a substring match on input_data JSON since agent_key is encoded there.
    marker = f'"agent_key": "{a.key}"'
    runs_30d = (
        db.query(func.count(AgentRun.id))
        .filter(AgentRun.started_at >= last_30)
        .filter(cast(AgentRun.input_data, String).ilike(f"%{marker}%"))
        .scalar() or 0
    )
    runs_total = (
        db.query(func.count(AgentRun.id))
        .filter(cast(AgentRun.input_data, String).ilike(f"%{marker}%"))
        .scalar() or 0
    )
    # Artifacts applied — counts agent_runs whose output_data contains "applied": true
    applied_30d = (
        db.query(func.count(AgentRun.id))
        .filter(AgentRun.started_at >= last_30)
        .filter(cast(AgentRun.input_data, String).ilike(f"%{marker}%"))
        .filter(cast(AgentRun.output_data, String).ilike('%"applied": true%'))
        .scalar() or 0
    )
    learnings = (
        db.query(func.count(MissionLearning.id))
        .filter(MissionLearning.agent_key == a.key)
        .scalar() or 0
    )
    last_run_row = (
        db.query(AgentRun.completed_at)
        .filter(cast(AgentRun.input_data, String).ilike(f"%{marker}%"))
        .order_by(AgentRun.completed_at.desc())
        .first()
    )
    last_run_at = last_run_row[0].isoformat() if last_run_row and last_run_row[0] else None
    return {
        "agent_id": a.id,
        "agent_key": a.key,
        "runs_total": int(runs_total),
        "runs_30d": int(runs_30d),
        "artifacts_applied_30d": int(applied_30d),
        "learnings_contributed": int(learnings),
        "last_run_at": last_run_at,
    }


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
