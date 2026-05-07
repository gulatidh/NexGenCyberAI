"""AI Provider settings and test endpoint."""
from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from pydantic import BaseModel
from core.security import get_current_user, require_admin
from core.ai_providers import list_providers, get_llm, AIProvider

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
    from core.config import get_settings
    s = get_settings()
    return {"default_provider": s.DEFAULT_AI_PROVIDER}
