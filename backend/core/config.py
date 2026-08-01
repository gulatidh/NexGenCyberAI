"""
NexGenCyberAI - Core Configuration
Loads all settings from environment variables / .env file.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import List, Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "NexGenCyberAI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENABLE_SWAGGER: bool = False  # set True in dev via env var; off by default in prod
    SECRET_KEY: str = "change-me-in-production"
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "https://nexgencyberai.azurewebsites.net"]

    # Azure Entra ID (OIDC / OAuth2)
    AZURE_TENANT_ID: str = ""
    AZURE_CLIENT_ID: str = ""
    AZURE_CLIENT_SECRET: str = ""
    AZURE_AUTHORITY: str = ""
    AZURE_SCOPE: List[str] = ["https://graph.microsoft.com/.default"]
    AZURE_JWKS_URI: str = ""

    # Database
    DATABASE_URL: str = "sqlite:///./nexgencyberai.db"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # ── AI Provider Selection ──────────────────────────────────────────────────
    # Set DEFAULT_AI_PROVIDER to one of: openai | azure_openai | anthropic | google_gemini | aws_bedrock
    DEFAULT_AI_PROVIDER: str = "azure_openai"

    # Phase 7B — proactive buddy triggers. OFF by default: firing real buddy
    # LLM runs inline during scan ingest can OOM small App Service plans (the
    # worker dies mid-request and findings fail to ingest). Operators can flip
    # this on once the runtime has headroom / runs work off the web worker.
    PROACTIVE_BUDDIES_ENABLED: bool = False

    # Azure OpenAI
    AZURE_OPENAI_API_KEY: str = ""
    AZURE_OPENAI_ENDPOINT: str = ""
    AZURE_OPENAI_DEPLOYMENT: str = "gpt-4o"
    AZURE_OPENAI_API_VERSION: str = "2024-02-15-preview"

    # OpenAI (direct)
    OPENAI_API_KEY: str = ""

    # Anthropic Claude
    ANTHROPIC_API_KEY: str = ""

    # Google Gemini
    GOOGLE_API_KEY: str = ""

    # AWS Bedrock
    AWS_BEDROCK_REGION: str = "us-east-1"
    AWS_BEDROCK_ACCESS_KEY: str = ""
    AWS_BEDROCK_SECRET_KEY: str = ""

    # Custom / OpenAI-compatible endpoint (Ollama on VM, Azure AI Foundry,
    # Together AI, Groq, or any OpenAI-spec server).
    # Base URL examples:
    #   Ollama on VM:         http://10.0.0.5:11434/v1
    #   Azure AI Foundry:     https://<name>.inference.ai.azure.com/v1
    #   Together AI:          https://api.together.xyz/v1
    CUSTOM_OPENAI_BASE_URL: str = ""
    CUSTOM_OPENAI_API_KEY: str = "ollama"   # Ollama accepts any non-empty string
    CUSTOM_OPENAI_MODEL: str = "qwen2.5-coder:72b"

    # ── Connector defaults ─────────────────────────────────────────────────────
    ENCRYPTION_KEY: str = ""
    AWS_DEFAULT_REGION: str = "us-east-1"
    GCP_PROJECT_ID: str = ""
    ARM_SUBSCRIPTION_ID: str = ""
    # Platform-wide NVD API key (free, from nvd.nist.gov). Used by OWASP
    # Dependency-Check scans when a connector doesn't carry its own key.
    # Set as a Key Vault-referenced App Service setting in prod.
    NVD_API_KEY: str = ""
    SCAN_INGEST_SECRET: str = ""

    # Access control — comma-separated list of UPNs that are automatically
    # bootstrapped as global admins on first login (no DB grant needed yet).
    # Example: "dheeraj@gretagulati.com,alice@gretagulati.com"
    # Leave empty after bootstrapping; do not use as a permanent bypass.
    INITIAL_ADMIN_EMAILS: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
