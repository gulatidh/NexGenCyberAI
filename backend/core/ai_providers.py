"""
NexGenCyberAI - Multi-Provider AI Abstraction Layer
Supports: Anthropic Claude, OpenAI GPT, Google Gemini, AWS Bedrock, Azure OpenAI.
Agents call get_llm() to get a LangChain-compatible LLM regardless of provider.
Provider and model are configurable per-client or globally via settings.

Automatic failover: if the primary provider fails to initialise (missing credentials,
external shutdown, export-control action, rate limit), get_llm() walks a priority
chain of all configured providers until one succeeds.  The fallback is logged at
WARNING level so it is always visible in App Service logs / Azure Monitor.
"""
from __future__ import annotations
import logging
from enum import Enum
from typing import Optional, Any
from langchain_core.language_models.chat_models import BaseChatModel
from core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


def _resolved(name: str) -> Optional[str]:
    """DB-first config lookup with env-var fallback. Imported lazily to avoid
    circular imports at module load."""
    try:
        from services.ai_settings import get_resolved_value
        return get_resolved_value(name)
    except Exception:
        return None


class AIProvider(str, Enum):
    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"
    ANTHROPIC = "anthropic"
    GOOGLE_GEMINI = "google_gemini"
    AWS_BEDROCK = "aws_bedrock"
    CUSTOM_OPENAI = "custom_openai"   # any OpenAI-compatible endpoint: Ollama, Azure AI Foundry, Together AI …


class ProviderUnavailableError(RuntimeError):
    """Raised when every configured AI provider fails to initialise.

    Attributes:
        primary   – the provider that was originally requested
        attempts  – ordered list of (provider_name, reason) tried before giving up
    """
    def __init__(self, primary: str, attempts: list[tuple[str, str]]) -> None:
        self.primary = primary
        self.attempts = attempts
        detail = "\n".join(f"  {p}: {reason}" for p, reason in attempts)
        super().__init__(
            f"All AI providers unavailable (primary was '{primary}'):\n{detail}"
        )


def _build_custom_openai(model: str = None, **kwargs) -> BaseChatModel:
    """Any OpenAI-compatible endpoint: Ollama on a VM, Azure AI Foundry,
    Together AI, Groq, etc.  Only the base_url differs between them."""
    from langchain_openai import ChatOpenAI
    base_url = _resolved("custom_openai_base_url") or settings.CUSTOM_OPENAI_BASE_URL
    if not base_url:
        raise ValueError(
            "custom_openai_base_url is not configured — set it to your endpoint, "
            "e.g. http://gpu-vm:11434/v1 for Ollama or "
            "https://<name>.inference.ai.azure.com/v1 for Azure AI Foundry"
        )
    model_name = model or _resolved("custom_openai_model") or settings.CUSTOM_OPENAI_MODEL
    # Ollama accepts any non-empty string as the API key; real services need a real key.
    api_key = _resolved("custom_openai_api_key") or settings.CUSTOM_OPENAI_API_KEY or "ollama"
    return ChatOpenAI(
        base_url=base_url,
        model=model_name,
        api_key=api_key,
        temperature=kwargs.get("temperature", 0.1),
        max_tokens=kwargs.get("max_tokens", 4096),
    )


# Failover priority when the primary provider is unavailable.
# The configured primary is always tried first; this list determines the order
# of the remaining candidates.  Azure OpenAI leads because it is sovereign to
# the tenant's own Azure subscription and unaffected by US export-control orders
# that target the Anthropic / OpenAI consumer APIs.
_FALLBACK_ORDER: list[AIProvider] = [
    AIProvider.AZURE_OPENAI,
    AIProvider.OPENAI,
    AIProvider.GOOGLE_GEMINI,
    AIProvider.AWS_BEDROCK,
    AIProvider.ANTHROPIC,
    AIProvider.CUSTOM_OPENAI,   # last resort — fully sovereign but requires extra infra
]


# ── Provider builders ──────────────────────────────────────────────────────────

def _build_openai(model: str = "gpt-4o", **kwargs) -> BaseChatModel:
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(
        model=model,
        api_key=_resolved("openai_api_key") or settings.OPENAI_API_KEY,
        temperature=kwargs.get("temperature", 0.1),
        max_tokens=kwargs.get("max_tokens", 4096),
    )


def _build_azure_openai(model: str = None, **kwargs) -> BaseChatModel:
    from langchain_openai import AzureChatOpenAI
    return AzureChatOpenAI(
        azure_endpoint=_resolved("azure_openai_endpoint") or settings.AZURE_OPENAI_ENDPOINT,
        azure_deployment=model or _resolved("azure_openai_deployment") or settings.AZURE_OPENAI_DEPLOYMENT,
        openai_api_version=_resolved("azure_openai_api_version") or settings.AZURE_OPENAI_API_VERSION,
        api_key=_resolved("azure_openai_api_key") or settings.AZURE_OPENAI_API_KEY,
        temperature=kwargs.get("temperature", 0.1),
        max_tokens=kwargs.get("max_tokens", 4096),
    )


def _build_anthropic(model: str = "claude-sonnet-4-6", **kwargs) -> BaseChatModel:
    from langchain_anthropic import ChatAnthropic
    return ChatAnthropic(
        model=model,
        api_key=_resolved("anthropic_api_key") or settings.ANTHROPIC_API_KEY,
        temperature=kwargs.get("temperature", 0.1),
        max_tokens=kwargs.get("max_tokens", 4096),
    )


def _build_gemini(model: str = "gemini-1.5-pro", **kwargs) -> BaseChatModel:
    from langchain_google_genai import ChatGoogleGenerativeAI
    return ChatGoogleGenerativeAI(
        model=model,
        google_api_key=_resolved("google_api_key") or settings.GOOGLE_API_KEY,
        temperature=kwargs.get("temperature", 0.1),
        max_output_tokens=kwargs.get("max_tokens", 4096),
    )


def _build_bedrock(model: str = "anthropic.claude-3-5-sonnet-20241022-v2:0", **kwargs) -> BaseChatModel:
    from langchain_aws import ChatBedrock
    import boto3
    session = boto3.Session(
        aws_access_key_id=_resolved("aws_bedrock_access_key") or settings.AWS_BEDROCK_ACCESS_KEY or None,
        aws_secret_access_key=_resolved("aws_bedrock_secret_key") or settings.AWS_BEDROCK_SECRET_KEY or None,
        region_name=_resolved("aws_bedrock_region") or settings.AWS_BEDROCK_REGION,
    )
    client = session.client("bedrock-runtime")
    return ChatBedrock(
        model_id=model,
        client=client,
        model_kwargs={"temperature": kwargs.get("temperature", 0.1), "max_tokens": kwargs.get("max_tokens", 4096)},
    )


# ── Credential check (fast path — no network) ─────────────────────────────────

def _is_configured(provider: AIProvider) -> bool:
    """Return True only if the minimum required credentials are present.

    This is a local check only — it does not make any network call.  It lets
    the failover loop skip providers that are obviously unconfigured rather than
    incurring a slow connection timeout.
    """
    if provider == AIProvider.AZURE_OPENAI:
        return bool(
            (_resolved("azure_openai_api_key") or settings.AZURE_OPENAI_API_KEY)
            and (_resolved("azure_openai_endpoint") or settings.AZURE_OPENAI_ENDPOINT)
        )
    if provider == AIProvider.OPENAI:
        return bool(_resolved("openai_api_key") or settings.OPENAI_API_KEY)
    if provider == AIProvider.ANTHROPIC:
        return bool(_resolved("anthropic_api_key") or settings.ANTHROPIC_API_KEY)
    if provider == AIProvider.GOOGLE_GEMINI:
        return bool(_resolved("google_api_key") or settings.GOOGLE_API_KEY)
    if provider == AIProvider.AWS_BEDROCK:
        return bool(_resolved("aws_bedrock_region") or settings.AWS_BEDROCK_REGION)
    if provider == AIProvider.CUSTOM_OPENAI:
        return bool(_resolved("custom_openai_base_url") or settings.CUSTOM_OPENAI_BASE_URL)
    return False


# ── Public API ─────────────────────────────────────────────────────────────────

_BUILDERS = {
    AIProvider.OPENAI: _build_openai,
    AIProvider.AZURE_OPENAI: _build_azure_openai,
    AIProvider.ANTHROPIC: _build_anthropic,
    AIProvider.GOOGLE_GEMINI: _build_gemini,
    AIProvider.AWS_BEDROCK: _build_bedrock,
    AIProvider.CUSTOM_OPENAI: _build_custom_openai,
}


def get_llm(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 4096,
) -> BaseChatModel:
    """Return a LangChain-compatible LLM, with automatic failover.

    Tries the requested provider first (or DEFAULT_AI_PROVIDER when none is
    given).  If it is unconfigured or raises on initialisation, walks
    _FALLBACK_ORDER until a provider succeeds.  Every fallover step is logged
    at WARNING level so it is visible in Azure Monitor / App Service logs.

    Raises:
        ProviderUnavailableError – all configured providers failed.
    """
    primary = AIProvider(provider or _resolved("default_provider") or settings.DEFAULT_AI_PROVIDER)

    # Primary first, then the rest of the fallback chain (excluding primary)
    candidates = [primary] + [p for p in _FALLBACK_ORDER if p != primary]

    attempts: list[tuple[str, str]] = []

    for candidate in candidates:
        builder = _BUILDERS.get(candidate)
        if builder is None:
            continue

        if not _is_configured(candidate):
            attempts.append((candidate.value, "not configured (missing credentials)"))
            continue

        # When failing over to a different provider don't forward a model name
        # that belongs to the original provider (e.g. "claude-opus-4-7" to Azure).
        effective_model = model if candidate == primary else None

        try:
            llm = builder(model=effective_model, temperature=temperature, max_tokens=max_tokens)
            if candidate != primary:
                logger.warning(
                    "AI provider failover: primary '%s' unavailable, using '%s'. "
                    "Attempts before success: %s",
                    primary.value, candidate.value, attempts,
                )
            return llm
        except Exception as exc:
            attempts.append((candidate.value, str(exc)))
            logger.warning(
                "AI provider '%s' failed to initialise: %s — trying next provider",
                candidate.value, exc,
            )

    raise ProviderUnavailableError(primary.value, attempts)


def get_embeddings(
    provider: Optional[str] = None,
    model: Optional[str] = None,
):
    """Return a LangChain Embeddings client for the requested provider.

    Used by services/learning_memory.py to embed extracted learnings for
    cosine-similarity retrieval. Defaults to OpenAI text-embedding-3-small
    (1536-d) — cheap, widely available. Azure OpenAI uses the same model
    family via a deployment name.

    Raises if no embedding-capable provider is configured."""
    from services.ai_settings import get_resolved_value
    try:
        cfg_provider = get_resolved_value("embedding_provider") or "openai"
    except Exception:
        cfg_provider = "openai"
    resolved = (provider or cfg_provider or "openai").lower()
    if resolved == "openai":
        from langchain_openai import OpenAIEmbeddings
        return OpenAIEmbeddings(
            model=model or _resolved("embedding_model") or "text-embedding-3-small",
            api_key=_resolved("openai_api_key") or settings.OPENAI_API_KEY,
        )
    if resolved == "azure_openai":
        from langchain_openai import AzureOpenAIEmbeddings
        return AzureOpenAIEmbeddings(
            azure_endpoint=_resolved("azure_openai_endpoint") or settings.AZURE_OPENAI_ENDPOINT,
            azure_deployment=model or _resolved("embedding_model") or "text-embedding-3-small",
            openai_api_version=_resolved("azure_openai_api_version") or settings.AZURE_OPENAI_API_VERSION,
            api_key=_resolved("azure_openai_api_key") or settings.AZURE_OPENAI_API_KEY,
        )
    raise ValueError(f"Unsupported embedding provider: {resolved}")


def list_providers() -> list[dict]:
    """Return all providers with their availability status."""
    azure_endpoint = _resolved("azure_openai_endpoint") or settings.AZURE_OPENAI_ENDPOINT
    azure_deploy = _resolved("azure_openai_deployment") or settings.AZURE_OPENAI_DEPLOYMENT
    custom_base = _resolved("custom_openai_base_url") or settings.CUSTOM_OPENAI_BASE_URL
    custom_model = _resolved("custom_openai_model") or settings.CUSTOM_OPENAI_MODEL
    availability = {
        AIProvider.OPENAI: bool(_resolved("openai_api_key") or settings.OPENAI_API_KEY),
        AIProvider.AZURE_OPENAI: bool((_resolved("azure_openai_api_key") or settings.AZURE_OPENAI_API_KEY) and azure_endpoint),
        AIProvider.ANTHROPIC: bool(_resolved("anthropic_api_key") or settings.ANTHROPIC_API_KEY),
        AIProvider.GOOGLE_GEMINI: bool(_resolved("google_api_key") or settings.GOOGLE_API_KEY),
        AIProvider.AWS_BEDROCK: bool(_resolved("aws_bedrock_region") or settings.AWS_BEDROCK_REGION),
        AIProvider.CUSTOM_OPENAI: bool(custom_base),
    }
    models = {
        AIProvider.OPENAI: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1", "o3-mini"],
        AIProvider.AZURE_OPENAI: sorted({
            "gpt-4o", "gpt-4.1", "gpt-4.1-mini", "gpt-4-turbo", "gpt-35-turbo",
            azure_deploy,  # always include the configured deployment
        }),
        AIProvider.ANTHROPIC: ["claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
        AIProvider.GOOGLE_GEMINI: ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"],
        AIProvider.AWS_BEDROCK: [
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "amazon.titan-text-express-v1",
            "meta.llama3-70b-instruct-v1:0",
            "mistral.mistral-large-2402-v1:0",
        ],
        AIProvider.CUSTOM_OPENAI: list({
            custom_model,
            "qwen2.5-coder:72b",
            "qwen2.5-coder:32b",
            "llama3.3:70b",
            "deepseek-r1:70b",
            "mistral:7b",
        }) if custom_base else ["qwen2.5-coder:72b", "llama3.3:70b", "deepseek-r1:70b"],
    }
    return [
        {
            "provider": p.value,
            "available": availability[p],
            "models": models[p],
        }
        for p in AIProvider
    ]
