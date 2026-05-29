"""AI Agent catalog API — browse for any authenticated user, CRUD for admins.

Admin check follows the same DB-grant pattern as admin.py — anyone with
admin role at any scope (global, client, or project) can create / modify /
delete agents. Built-in agents (`is_builtin=True`) cannot be deleted via
the API; admins can edit them. New agents are always `is_builtin=False`.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
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


class AgentRunResponse(BaseModel):
    agent_id: str
    agent_name: str
    output: str
    provider: str
    model: Optional[str] = None
    tokens_used: int = 0
    duration_ms: int = 0


@router.post("/{agent_id}/run", response_model=AgentRunResponse)
async def run_agent(
    agent_id: str,
    payload: AgentRunRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Execute a catalog agent against an optional client context.

    Catalog agents are advisory: we ship the system prompt + the user's
    instruction to the configured LLM provider and return the completion.
    Legacy operational agents (`legacy_orchestrator=True`) are not run via
    this path — they have their own routers at `/clients/{client_id}/agents/run/`.
    """
    import time
    from core.ai_providers import get_llm
    from langchain_core.messages import HumanMessage, SystemMessage

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

    instruction = (payload.prompt or "").strip() or (
        f"Provide your standard briefing on {a.domain or a.name}. "
        f"Be concise and senior-level. Cite framework controls where relevant."
    )

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
    # Extract text + token count from various LangChain BaseChatModel shapes
    text = result.content if hasattr(result, "content") else str(result)
    if isinstance(text, list):
        text = "\n".join(str(p) for p in text)
    usage = getattr(result, "usage_metadata", None) or {}
    tokens = int(usage.get("total_tokens") or 0)

    return AgentRunResponse(
        agent_id=a.id,
        agent_name=a.name,
        output=text,
        provider=a.provider or "default",
        model=a.model,
        tokens_used=tokens,
        duration_ms=duration_ms,
    )
