"""
NexGenCyberAI - Multi-Provider AI Abstraction Layer
Supports: Anthropic Claude, OpenAI GPT, Google Gemini, AWS Bedrock.
Agents call get_llm() to get a LangChain-compatible LLM regardless of provider.
Provider and model are configurable per-client or globally via settings.
"""
from __future__ import annotations
from enum import Enum
from typing import Optional, Any
from langchain_core.language_models.chat_models import BaseChatModel
from core.config import get_settings

settings = get_settings()


class AIProvider(str, Enum):
    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"
    ANTHROPIC = "anthropic"
    GOOGLE_GEMINI = "google_gemini"
    AWS_BEDROCK = "aws_bedrock"


# ── Provider builders ──────────────────────────────────────────────────────────

def _build_openai(model: str = "gpt-4o", **kwargs) -> BaseChatModel:
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(
        model=model,
        api_key=settings.OPENAI_API_KEY,
        temperature=kwargs.get("temperature", 0.1),
        max_tokens=kwargs.get("max_tokens", 4096),
    )


def _build_azure_openai(model: str = None, **kwargs) -> BaseChatModel:
    from langchain_openai import AzureChatOpenAI
    return AzureChatOpenAI(
        azure_endpoint=settings.AZURE_OPENAI_ENDPOINT,
        azure_deployment=model or settings.AZURE_OPENAI_DEPLOYMENT,
        openai_api_version=settings.AZURE_OPENAI_API_VERSION,
        api_key=settings.AZURE_OPENAI_API_KEY,
        temperature=kwargs.get("temperature", 0.1),
        max_tokens=kwargs.get("max_tokens", 4096),
    )


def _build_anthropic(model: str = "claude-sonnet-4-6", **kwargs) -> BaseChatModel:
    from langchain_anthropic import ChatAnthropic
    return ChatAnthropic(
        model=model,
        api_key=settings.ANTHROPIC_API_KEY,
        temperature=kwargs.get("temperature", 0.1),
        max_tokens=kwargs.get("max_tokens", 4096),
    )


def _build_gemini(model: str = "gemini-1.5-pro", **kwargs) -> BaseChatModel:
    from langchain_google_genai import ChatGoogleGenerativeAI
    return ChatGoogleGenerativeAI(
        model=model,
        google_api_key=settings.GOOGLE_API_KEY,
        temperature=kwargs.get("temperature", 0.1),
        max_output_tokens=kwargs.get("max_tokens", 4096),
    )


def _build_bedrock(model: str = "anthropic.claude-3-5-sonnet-20241022-v2:0", **kwargs) -> BaseChatModel:
    from langchain_aws import ChatBedrock
    import boto3
    session = boto3.Session(
        aws_access_key_id=settings.AWS_BEDROCK_ACCESS_KEY or None,
        aws_secret_access_key=settings.AWS_BEDROCK_SECRET_KEY or None,
        region_name=settings.AWS_BEDROCK_REGION,
    )
    client = session.client("bedrock-runtime")
    return ChatBedrock(
        model_id=model,
        client=client,
        model_kwargs={"temperature": kwargs.get("temperature", 0.1), "max_tokens": kwargs.get("max_tokens", 4096)},
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_BUILDERS = {
    AIProvider.OPENAI: _build_openai,
    AIProvider.AZURE_OPENAI: _build_azure_openai,
    AIProvider.ANTHROPIC: _build_anthropic,
    AIProvider.GOOGLE_GEMINI: _build_gemini,
    AIProvider.AWS_BEDROCK: _build_bedrock,
}


def get_llm(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 4096,
) -> BaseChatModel:
    """
    Return a LangChain-compatible LLM for the requested provider.
    Falls back to settings.DEFAULT_AI_PROVIDER if provider is None.
    """
    resolved_provider = AIProvider(provider or settings.DEFAULT_AI_PROVIDER)
    builder = _BUILDERS.get(resolved_provider)
    if builder is None:
        raise ValueError(f"Unsupported AI provider: {resolved_provider}")
    try:
        return builder(model=model, temperature=temperature, max_tokens=max_tokens)
    except Exception as exc:
        raise RuntimeError(f"Failed to initialise {resolved_provider} LLM: {exc}") from exc


def list_providers() -> list[dict]:
    """Return all providers with their availability status."""
    availability = {
        AIProvider.OPENAI: bool(settings.OPENAI_API_KEY),
        AIProvider.AZURE_OPENAI: bool(settings.AZURE_OPENAI_API_KEY and settings.AZURE_OPENAI_ENDPOINT),
        AIProvider.ANTHROPIC: bool(settings.ANTHROPIC_API_KEY),
        AIProvider.GOOGLE_GEMINI: bool(settings.GOOGLE_API_KEY),
        AIProvider.AWS_BEDROCK: bool(settings.AWS_BEDROCK_REGION),
    }
    models = {
        AIProvider.OPENAI: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1", "o3-mini"],
        AIProvider.AZURE_OPENAI: ["gpt-4o", "gpt-4-turbo", "gpt-35-turbo"],
        AIProvider.ANTHROPIC: ["claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
        AIProvider.GOOGLE_GEMINI: ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"],
        AIProvider.AWS_BEDROCK: [
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "amazon.titan-text-express-v1",
            "meta.llama3-70b-instruct-v1:0",
            "mistral.mistral-large-2402-v1:0",
        ],
    }
    return [
        {
            "provider": p.value,
            "available": availability[p],
            "models": models[p],
        }
        for p in AIProvider
    ]
