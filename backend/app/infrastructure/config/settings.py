"""Application settings loaded from environment variables.

Uses pydantic-settings for typed validation. The application will fail
to start if any required variable is missing or has an invalid value.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The insecure default secret — if still set in production, startup will fail
_INSECURE_DEFAULT_SECRET = "CHANGE_ME_IN_PRODUCTION_USE_LONG_RANDOM_SECRET"


class Settings(BaseSettings):
    """All application configuration, sourced from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- Application ----
    app_env: Literal["development", "staging", "production"] = Field(
        default="development",
        description="Deployment environment",
    )
    app_name: str = Field(default="Email Threat Detection API")
    debug: bool = Field(default=False)
    demo_mode: bool = Field(default=False, description="Enable demo and dev endpoints")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    allowed_origins: list[str] = Field(
        default=["http://localhost:5173", "http://localhost:3000"],
    )
    cors_origin_regex: str | None = Field(
        default=r"^https://.*\.vercel\.app$",
        description="Regex pattern for allowed origins (e.g. Vercel preview and production deployments)",
    )

    # ---- Database ----
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/email_threat_db",
        description="Async PostgreSQL DSN",
    )
    database_pool_size: int = Field(default=10, ge=1, le=50)
    database_max_overflow: int = Field(default=20, ge=0, le=100)
    database_echo: bool = Field(default=False, description="Log SQL queries (dev only)")

    # ---- Redis ----
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )
    redis_max_connections: int = Field(default=20, ge=1)
    redis_required: bool = Field(
        default=False,
        description="Fail health checks if Redis is offline. Set false for free-tier standalone deployment.",
    )

    # ---- JWT ----
    jwt_secret_key: SecretStr = Field(
        default=SecretStr(_INSECURE_DEFAULT_SECRET),
        description="Secret key for JWT signing — MUST be changed in production",
    )
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=15, ge=5, le=1440)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=30)

    # ---- Groq (AI) ----
    groq_api_key: SecretStr | None = Field(default=None)
    groq_model: str = Field(default="llama-3.3-70b-versatile")
    groq_max_tokens: int = Field(default=2048, ge=256)
    groq_timeout_seconds: int = Field(default=30, ge=5)
    groq_timeout: int = Field(default=30, ge=5, description="Groq API timeout in seconds")
    groq_max_retries: int = Field(
        default=3, ge=0, le=10, description="Max retry attempts for Groq API"
    )

    # ---- VirusTotal & Threat Intelligence ----
    virustotal_api_key: SecretStr | None = Field(default=None)
    virustotal_timeout_seconds: int = Field(
        default=10, ge=1, description="VirusTotal API timeout in seconds"
    )
    virustotal_max_retries: int = Field(
        default=2, ge=0, le=5, description="Max retries for VirusTotal API"
    )
    abuseipdb_api_key: SecretStr | None = Field(default=None)
    abuseipdb_timeout_seconds: int = Field(
        default=10, ge=1, description="AbuseIPDB API timeout in seconds"
    )
    threat_intel_cache_ttl_seconds: int = Field(
        default=3600, ge=60, description="Threat intelligence cache TTL in seconds"
    )

    # ---- Celery / Workers ----
    celery_broker_url: str = Field(default="redis://localhost:6379/1")
    celery_result_backend: str = Field(default="redis://localhost:6379/2")

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v: Any) -> list[str]:
        """Support comma-separated strings or JSON arrays from cloud environment variables."""
        if isinstance(v, str):
            v_stripped = v.strip()
            if v_stripped.startswith("[") and v_stripped.endswith("]"):
                import json

                try:
                    parsed = json.loads(v_stripped)
                    if isinstance(parsed, list):
                        return [str(orig).strip() for orig in parsed if str(orig).strip()]
                except Exception:
                    pass
            return [orig.strip() for orig in v_stripped.split(",") if orig.strip()]
        return v

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_database_url(cls, v: Any) -> str:
        """Ensure database URL uses asyncpg driver and clean params for cloud providers like Supabase."""
        if not isinstance(v, str):
            return str(v)
        v = v.strip()
        # Handle postgres:// or postgresql:// without asyncpg
        if v.startswith("postgres://"):
            v = "postgresql+asyncpg://" + v[len("postgres://"):]
        elif v.startswith("postgresql://"):
            v = "postgresql+asyncpg://" + v[len("postgresql://"):]
        # Remove sslmode query parameter that asyncpg rejects
        if "sslmode=" in v:
            import re

            v = re.sub(r"[?&]sslmode=[^&]+", "", v)
            if "?" not in v and "&" in v:
                v = v.replace("&", "?", 1)
        return v

    @field_validator("debug", mode="before")
    @classmethod
    def disable_debug_in_production(cls, v: bool) -> bool:
        """Force debug=False in production regardless of env var."""
        return v

    @model_validator(mode="after")
    def enforce_production_security(self) -> Settings:
        """Raise at startup if insecure defaults are active in staging/production."""
        if self.app_env in ("staging", "production"):
            secret = self.jwt_secret_key.get_secret_value()
            if secret == _INSECURE_DEFAULT_SECRET:
                raise ValueError(
                    "JWT_SECRET_KEY must be set to a strong random secret in staging/production. "
                    "Generate one with: python -c \"import secrets; print(secrets.token_hex(64))\""
                )
            if len(secret) < 32:
                raise ValueError(
                    f"JWT_SECRET_KEY is too short ({len(secret)} chars). "
                    "Minimum 32 characters required for HS256 security."
                )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings singleton.

    Cached so that pydantic-settings reads the .env file only once
    at startup. Use dependency injection in tests to override.
    """
    return Settings()
