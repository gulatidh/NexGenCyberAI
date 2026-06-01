"""AI Provider settings and test endpoint."""
from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session
from core.security import get_current_user
from core.ai_providers import list_providers, get_llm, AIProvider
from core.authz import require_role, _user_email
from db.database import get_db
from api.models.models import AccessRole
from services.ai_settings import get_config_safe, update_config

router = APIRouter(prefix="/ai", tags=["ai-settings"])


class AITestRequest(BaseModel):
    provider: str
    model: Optional[str] = None
    prompt: str = "Say 'NexGenCyberAI connection test successful' in one sentence."


class AITestResponse(BaseModel):
    provider: str
    model: Optional[str]
    response: str
    success: bool
    error: Optional[str] = None


class AIConfigUpdate(BaseModel):
    """All fields optional. For secret fields, send the new value to update,
    "" to clear, or omit to leave unchanged."""
    default_provider: Optional[str] = None
    default_model: Optional[str] = None
    default_temperature: Optional[float] = None
    azure_openai_endpoint: Optional[str] = None
    azure_openai_deployment: Optional[str] = None
    azure_openai_api_version: Optional[str] = None
    aws_bedrock_region: Optional[str] = None
    openai_api_key: Optional[str] = None
    azure_openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    google_api_key: Optional[str] = None
    aws_bedrock_access_key: Optional[str] = None
    aws_bedrock_secret_key: Optional[str] = None
    # Phase 5 — learning memory + critique + blackboard
    embedding_provider: Optional[str] = None
    embedding_model: Optional[str] = None
    self_critique_enabled: Optional[bool] = None
    semantic_learning_enabled: Optional[bool] = None
    blackboard_enabled: Optional[bool] = None


@router.get("/providers/")
async def get_providers(_=Depends(get_current_user)):
    """List all supported AI providers and their availability."""
    return {"providers": list_providers()}


@router.post("/test/", response_model=AITestResponse)
async def test_ai_provider(payload: AITestRequest, _=Depends(get_current_user)):
    """Test connectivity to an AI provider with a simple prompt."""
    try:
        llm = get_llm(provider=payload.provider, model=payload.model)
        from langchain_core.messages import HumanMessage
        result = llm.invoke([HumanMessage(content=payload.prompt)])
        content = result.content if hasattr(result, "content") else str(result)
        return AITestResponse(
            provider=payload.provider,
            model=payload.model,
            response=content,
            success=True,
        )
    except Exception as exc:
        return AITestResponse(
            provider=payload.provider,
            model=payload.model,
            response="",
            success=False,
            error=str(exc),
        )


@router.get("/default-provider/")
async def get_default_provider(_=Depends(get_current_user)):
    from services.ai_settings import get_resolved_value
    from core.config import get_settings
    return {"default_provider": get_resolved_value("default_provider") or get_settings().DEFAULT_AI_PROVIDER}


@router.get("/config/")
async def get_ai_config(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Return the current AI configuration. Secret fields are returned as
    `<field>_configured` booleans + `<field>_source` ("db"|"env"|"none") —
    actual key material is never echoed back."""
    return get_config_safe(db)


@router.patch("/config/")
async def update_ai_config(
    payload: AIConfigUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_role(AccessRole.ADMIN)),
):
    """Admin-only. Persist provider keys/endpoints/defaults so users don't
    have to redeploy with env vars."""
    update_config(db, payload.model_dump(exclude_unset=True), updated_by=_user_email(user))
    return get_config_safe(db)


@router.get("/learning-stats/")
async def get_learning_stats(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Phase 5 — telemetry on the learning loop. Lets the operator see that
    extraction is firing, embeddings are populating, and the blackboard is
    being used. All counts include the lifetime of the table (no scope filter)."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func
    from api.models.models import AgentRun, MissionLearning, ScanBlackboardEntry

    now = datetime.now(timezone.utc)
    last_30 = now - timedelta(days=30)

    total_learnings = db.query(func.count(MissionLearning.id)).scalar() or 0
    learnings_30d = (
        db.query(func.count(MissionLearning.id))
        .filter(MissionLearning.created_at >= last_30)
        .scalar() or 0
    )
    with_embeddings = (
        db.query(func.count(MissionLearning.id))
        .filter(MissionLearning.embedding_json.isnot(None))
        .scalar() or 0
    )
    by_category_rows = (
        db.query(MissionLearning.category, func.count(MissionLearning.id))
        .group_by(MissionLearning.category)
        .all()
    )
    by_category = {(c or "unknown"): int(n) for c, n in by_category_rows}

    bb_total = db.query(func.count(ScanBlackboardEntry.id)).scalar() or 0
    bb_30d = (
        db.query(func.count(ScanBlackboardEntry.id))
        .filter(ScanBlackboardEntry.created_at >= last_30)
        .scalar() or 0
    )

    # Self-critique count: AgentRuns whose output_data contains a 'critique' key.
    # JSON-path queries differ per dialect — keep this simple by counting all
    # rows where the marker substring appears in the JSON text. Cheap enough
    # for any realistic AgentRun volume.
    critique_recent = 0
    try:
        critique_recent = (
            db.query(func.count(AgentRun.id))
            .filter(AgentRun.started_at >= last_30)
            .filter(func.cast(AgentRun.output_data, type_=__import__("sqlalchemy").Text).ilike("%\"critique\"%"))
            .scalar() or 0
        )
    except Exception:
        critique_recent = 0

    return {
        "learnings": {
            "total": int(total_learnings),
            "last_30d": int(learnings_30d),
            "with_embeddings": int(with_embeddings),
            "by_category": by_category,
        },
        "blackboard": {
            "total": int(bb_total),
            "last_30d": int(bb_30d),
        },
        "self_critique": {
            "runs_30d": int(critique_recent),
        },
    }
