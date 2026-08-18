"""Platform Assistant — context-injected chat endpoint powered by the configured LLM provider."""
import logging
import time
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from core.ai_providers import ProviderUnavailableError, get_llm
from core.security import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(tags=["assistant"])

_CONTEXT_PATH = Path(__file__).parent.parent.parent / "data" / "portal_assistant_context.md"


def _load_context() -> str:
    try:
        return _CONTEXT_PATH.read_text(encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not load assistant context: %s", exc)
        return ""


class _Msg(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., max_length=4000, description="User message — max 4000 characters")
    current_page: Optional[str] = None
    history: Optional[List[_Msg]] = []


class ChatResponse(BaseModel):
    reply: str


@router.post("/assistant/chat", response_model=ChatResponse)
async def chat(payload: ChatRequest, user=Depends(get_current_user)):
    """Answer a platform usage question using injected portal documentation."""
    context = _load_context()
    page_hint = f"\n\nThe user is currently on page: {payload.current_page}" if payload.current_page else ""

    system_content = (
        "You are the Owlet AI Platform Assistant — an expert on the Owlet AI cybersecurity "
        "platform. Answer questions about features, workflows, and troubleshooting based on "
        "the documentation below. Be concise and specific. Always tell the user exactly where "
        "to click or navigate. If something isn't covered in the documentation, say so honestly "
        "rather than guessing."
        f"{page_hint}"
        "\n\n--- PLATFORM DOCUMENTATION ---\n\n"
        f"{context}"
    )

    _t1 = time.time()
    try:
        llm = get_llm()
    except ProviderUnavailableError:
        raise HTTPException(
            status_code=503,
            detail="No AI provider is configured. Go to AI Settings and set up Azure OpenAI (or another provider) to use the assistant.",
        )

    messages: list = [SystemMessage(content=system_content)]
    for msg in (payload.history or [])[-12:]:
        if msg.role == "user":
            messages.append(HumanMessage(content=msg.content))
        elif msg.role == "assistant":
            messages.append(AIMessage(content=msg.content))
    messages.append(HumanMessage(content=f"<user_message>{payload.message}</user_message>"))

    try:
        response = await llm.ainvoke(messages)
        _latency = int((time.time() - _t1) * 1000)
        try:
            from core.ai_providers import log_llm_call
            _uid = (user.get("sub") or user.get("upn") or user.get("email") or user.get("unique_name") or "unknown") if isinstance(user, dict) else "unknown"
            log_llm_call(
                endpoint="assistant_chat",
                user_id=_uid,
                provider=getattr(llm, "_llm_type", ""),
                input_chars=len(payload.message),
                output_chars=len(str(response.content)),
                latency_ms=_latency,
                status="ok",
            )
        except Exception:
            pass
        return ChatResponse(reply=str(response.content))
    except Exception as exc:
        logger.exception("Assistant LLM call failed")
        raise HTTPException(status_code=500, detail=f"AI error: {exc}")
