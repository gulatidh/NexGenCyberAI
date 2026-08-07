"""Platform Assistant — context-injected chat endpoint powered by the configured LLM provider."""
import logging
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
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
    message: str
    current_page: Optional[str] = None
    history: Optional[List[_Msg]] = []


class ChatResponse(BaseModel):
    reply: str


@router.post("/assistant/chat", response_model=ChatResponse)
async def chat(payload: ChatRequest, _=Depends(get_current_user)):
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
    messages.append(HumanMessage(content=payload.message))

    try:
        response = await llm.ainvoke(messages)
        return ChatResponse(reply=str(response.content))
    except Exception as exc:
        logger.exception("Assistant LLM call failed")
        raise HTTPException(status_code=500, detail=f"AI error: {exc}")
