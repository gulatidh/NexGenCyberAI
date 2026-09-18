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
from db.database import SessionLocal
from api.models.models import SystemKBEntry, LocalRunnerTool, LocalRunnerRegistration

logger = logging.getLogger(__name__)
router = APIRouter(tags=["assistant"])

_CONTEXT_PATH = Path(__file__).parent.parent.parent / "data" / "portal_assistant_context.md"


def _load_context() -> str:
    try:
        return _CONTEXT_PATH.read_text(encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not load assistant context: %s", exc)
        return ""


def _load_local_runner_context(current_page: str | None) -> str:
    """Inject live local runner state when the user is on a runner-related page."""
    if not current_page or "local-runner" not in current_page.lower():
        return ""
    try:
        db = SessionLocal()
        try:
            import json as _json
            tools = db.query(LocalRunnerTool).all()
            registrations = db.query(LocalRunnerRegistration).all()

            lines = ["\n## Live Local Runner State\n"]

            if tools:
                lines.append("### Installed tools on this machine")
                lines.append("| Tool | Installed | Version | Mode |")
                lines.append("|---|---|---|---|")
                for t in tools:
                    installed = "✅ Yes" if t.installed else "❌ No"
                    version = t.version or "—"
                    mode = t.mode or "github_actions"
                    lines.append(f"| {t.tool_name} | {installed} | {version} | {mode} |")
            else:
                lines.append("No local runner tools found in database — likely running against the cloud portal, not a local instance.")

            if registrations:
                from datetime import datetime, timezone
                lines.append("\n### Registered remote runners (paired with this cloud portal)")
                for r in registrations:
                    from api.routers.runner_registry import _age_status
                    status = _age_status(r.last_seen_at)
                    tool_data = []
                    if r.tools_json:
                        try:
                            tool_data = _json.loads(r.tools_json)
                        except Exception:
                            pass
                    installed_n = sum(1 for t in tool_data if t.get("installed"))
                    local_n = sum(1 for t in tool_data if t.get("mode") == "local")
                    last_seen = r.last_seen_at.strftime("%Y-%m-%d %H:%M UTC") if r.last_seen_at else "never"
                    lines.append(
                        f"- **{r.name}** ({r.machine_name or 'unknown machine'}) — "
                        f"status: {status}, last seen: {last_seen}, "
                        f"Kali: {'yes' if r.is_kali else 'no'}, "
                        f"{installed_n} tools installed, {local_n} running locally"
                    )

            lines.append(
                "\n_Use the information above to give specific advice about what the user "
                "needs to do next to set up or configure their local runner._"
            )
            return "\n".join(lines)
        finally:
            db.close()
    except Exception as exc:
        logger.warning("Could not load local runner context: %s", exc)
        return ""


def _load_system_kb() -> str:
    """Load all system KB entries from the database and format as a reference block."""
    try:
        db = SessionLocal()
        try:
            entries = db.query(SystemKBEntry).order_by(SystemKBEntry.section_key).all()
            if not entries:
                return ""
            parts = ["## Owlet Technical Reference\n"]
            for e in entries:
                parts.append(f"### {e.section_title}\n\n{e.content}\n")
            return "\n".join(parts)
        finally:
            db.close()
    except Exception as exc:
        logger.warning("Could not load system KB: %s", exc)
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
    """Answer a platform usage question using injected portal documentation and system KB."""
    context = _load_context()
    system_kb = _load_system_kb()
    runner_ctx = _load_local_runner_context(payload.current_page)
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
        + (f"\n\n--- TECHNICAL REFERENCE ---\n\n{system_kb}" if system_kb else "")
        + (f"\n\n--- LIVE RUNNER STATE ---\n\n{runner_ctx}" if runner_ctx else "")
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
