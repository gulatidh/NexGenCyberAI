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

    # ── Connector defaults ─────────────────────────────────────────────────────
    ENCRYPTION_KEY: str = ""
    AWS_DEFAULT_REGION: str = "us-east-1"
    GCP_PROJECT_ID: str = ""
    ARM_SUBSCRIPTION_ID: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
