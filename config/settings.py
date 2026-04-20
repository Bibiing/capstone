"""
Centralized application configuration powered by pydantic-settings.

All settings are sourced from environment variables or a .env file.
Sensitive values (passwords, keys) use SecretStr to prevent accidental logging.

Usage:
    from config.settings import get_settings

    settings = get_settings()
    print(settings.wazuh_api_url)
    # Access secrets explicitly:
    settings.wazuh_api_password.get_secret_value()

Notes:
    - get_settings() is LRU-cached — only one Settings instance per process.
    - Call get_settings.cache_clear() in tests to force reload.
    - WEIGHT_VULNERABILITY + WEIGHT_THREAT must always sum to 1.0 (validated).
"""

import logging
from functools import lru_cache

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """
    Application-wide settings loaded from environment variables.

    All fields map directly to env var names (case-insensitive).
    Example: WAZUH_API_URL → wazuh_api_url
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # Silently ignore unknown env vars
    )

    # ── Wazuh Manager REST API ─────────────────────────────────────────────────
    wazuh_api_url: str = Field(
        default="https://20.194.14.146:55000",
        description="Wazuh Manager REST API base URL (recommended: https://HOST:55000).",
    )
    wazuh_api_user: str = Field(
        default="wazuh-wui",
        description="Wazuh API username.",
    )
    wazuh_api_password: SecretStr = Field(
        default=SecretStr("CHANGE_ME"),
        description="Wazuh API password. Set via WAZUH_API_PASSWORD env var.",
    )

    # ── Wazuh Indexer (OpenSearch) ─────────────────────────────────────────────
    wazuh_indexer_url: str = Field(
        default="https://20.194.14.146:9200",
        description="Wazuh Indexer (OpenSearch) base URL (no trailing slash).",
    )
    wazuh_indexer_user: str = Field(
        default="admin",
        description="OpenSearch admin username.",
    )
    wazuh_indexer_password: SecretStr = Field(
        default=SecretStr("CHANGE_ME"),
        description="OpenSearch admin password. Set via WAZUH_INDEXER_PASSWORD env var.",
    )

    # ── Wazuh Connection Options ───────────────────────────────────────────────
    wazuh_verify_ssl: bool = Field(
        default=False,
        description=(
            "Verify Wazuh SSL certificate. Set to False for self-signed lab certs. "
            "MUST be True in any environment with valid certificates."
        ),
    )
    wazuh_api_timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="HTTP request timeout in seconds.",
    )
    wazuh_api_auth_path: str = Field(
        default="/security/user/authenticate",
        description="Relative auth path on Wazuh Manager API.",
    )
    wazuh_api_auth_use_raw: bool = Field(
        default=True,
        description=(
            "Append ?raw=true during auth to retrieve plain JWT token. "
            "Recommended for Wazuh Manager API compatibility."
        ),
    )
    wazuh_api_auto_port_discovery: bool = Field(
        default=True,
        description=(
            "If WAZUH_API_URL has no explicit port and auth returns 404, "
            "automatically retry auth against port 55000."
        ),
    )
    wazuh_max_retries: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Max retry attempts on transient Wazuh API failures.",
    )

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = Field(
        default="postgresql://capstone:capstone_dev@localhost:5432/risk_scoring",
        description="SQLAlchemy-compatible PostgreSQL connection string.",
    )
    db_pool_size: int = Field(
        default=5,
        ge=1,
        le=50,
        description="SQLAlchemy connection pool size.",
    )
    db_max_overflow: int = Field(
        default=10,
        ge=0,
        le=50,
        description="Max connections above pool_size allowed temporarily.",
    )
    db_pool_timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="Seconds to wait for a connection from the pool.",
    )

    # ── Scoring Engine ────────────────────────────────────────────────────────
    scoring_interval_hours: int = Field(
        default=1,
        ge=1,
        le=24,
        description="How often (hours) the scoring engine runs a full cycle.",
    )
    scoring_scheduler_enabled: bool = Field(
        default=False,
        description="Enable background APScheduler jobs inside API process.",
    )
    alert_lookback_hours: int = Field(
        default=1,
        ge=1,
        le=24,
        description="Window (hours) for fetching Wazuh alerts per scoring cycle.",
    )
    decay_factor: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description=(
            "Time decay factor α. Applied as: T_now = T_new + (T_prev × α). "
            "0.5 = 50%% of last period's threat carries forward."
        ),
    )
    weight_vulnerability: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="w1: SCA/CIS vulnerability weight in the final risk formula.",
    )
    weight_threat: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="w2: Active alert/threat weight in the final risk formula.",
    )

    # ── Firebase Authentication ───────────────────────────────────────────────
    firebase_project_id: str = Field(
        default="",
        description="Firebase project ID used to validate incoming ID tokens.",
    )
    firebase_web_api_key: str = Field(
        default="",
        description=(
            "Firebase Web API key used for Identity Toolkit actions "
            "(send email verification / password reset)."
        ),
    )
    firebase_service_account_json: str | None = Field(
        default=None,
        description="Inline JSON string for Firebase service account credentials.",
    )
    firebase_account_type: str = Field(
        default="service_account",
        description="Service account type for split Firebase credential fields.",
    )
    firebase_private_key_id: str | None = Field(
        default=None,
        description="Firebase service account private_key_id.",
    )
    firebase_private_key: str | None = Field(
        default=None,
        description="Firebase service account private_key (use escaped \\n in .env).",
    )
    firebase_client_email: str | None = Field(
        default=None,
        description="Firebase service account client_email.",
    )
    firebase_client_id: str | None = Field(
        default=None,
        description="Firebase service account client_id.",
    )
    firebase_auth_uri: str = Field(
        default="https://accounts.google.com/o/oauth2/auth",
        description="Firebase service account auth_uri.",
    )
    firebase_token_uri: str = Field(
        default="https://oauth2.googleapis.com/token",
        description="Firebase service account token_uri.",
    )
    firebase_auth_provider_x509_cert_url: str = Field(
        default="https://www.googleapis.com/oauth2/v1/certs",
        description="Firebase service account auth_provider_x509_cert_url.",
    )
    firebase_client_x509_cert_url: str | None = Field(
        default=None,
        description=(
            "Optional Firebase client_x509_cert_url. "
            "If omitted, it is derived from FIREBASE_CLIENT_EMAIL."
        ),
    )
    firebase_universe_domain: str = Field(
        default="googleapis.com",
        description="Firebase service account universe_domain.",
    )
    firebase_require_verified_email: bool = Field(
        default=True,
        description="Require Firebase email_verified=true before backend session activation.",
    )

    # ── JWT & Auth Configuration ──────────────────────────────────────────────
    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm (HS256 or RS256).",
    )
    jwt_expiration_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="JWT access token expiration time in hours.",
    )
    auth_register_limit_per_hour: int = Field(
        default=10,
        ge=1,
        le=500,
        description="Max register requests per email per hour.",
    )
    auth_login_limit_per_15m: int = Field(
        default=30,
        ge=1,
        le=500,
        description="Max login requests per email per 15 minutes.",
    )
    auth_password_reset_limit_per_hour: int = Field(
        default=10,
        ge=1,
        le=500,
        description="Max password reset requests per email per hour.",
    )

    # ── REST API ──────────────────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0", description="FastAPI server host.")
    api_port: int = Field(
        default=8000, ge=1024, le=65535, description="FastAPI server port."
    )
    api_environment: str = Field(
        default="development",
        description="Environment: 'development', 'staging', or 'production'.",
    )
    api_secret_key: SecretStr = Field(
        default=SecretStr("dev_secret_CHANGE_IN_PRODUCTION"),
        description=(
            "Secret key for JWT signing. "
            "Generate: python -c \"import secrets; print(secrets.token_hex(32))\""
        ),
    )
    # ── Dashboard ─────────────────────────────────────────────────────────────
    dashboard_api_url: str = Field(
        default="http://localhost:8000",
        description="Base URL of the FastAPI backend (used by Streamlit dashboard).",
    )
    dashboard_rate_limit_per_minute: int = Field(
        default=120,
        ge=10,
        le=2000,
        description="Max dashboard read requests per identity (token/IP) per minute.",
    )
    dashboard_rate_limit_window_seconds: int = Field(
        default=60,
        ge=10,
        le=3600,
        description="Rate limit window size in seconds for dashboard endpoints.",
    )
    metrics_enabled: bool = Field(
        default=True,
        description="Enable in-memory API metrics collection and metrics endpoint.",
    )

    # ── Cross-field Validation ────────────────────────────────────────────────
    @model_validator(mode="after")
    def validate_weights_sum_to_one(self) -> "Settings":
        """Ensure w1 + w2 == 1.0 to keep risk score in the 0–100 range."""
        total = round(self.weight_vulnerability + self.weight_threat, 6)
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"WEIGHT_VULNERABILITY ({self.weight_vulnerability}) + "
                f"WEIGHT_THREAT ({self.weight_threat}) must sum to 1.0, got {total}."
            )
        return self

    @field_validator("wazuh_api_url", "wazuh_indexer_url", "dashboard_api_url")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        """Normalize URLs — remove accidental trailing slashes."""
        return v.rstrip("/")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return a cached Settings instance (singleton per process).

    Reads from environment variables and .env file on first call.
    Call get_settings.cache_clear() in tests to force a reload.
    """
    settings = Settings()
    logger.info(
        "Configuration loaded | wazuh=%s | indexer=%s | db_pool=%d | decay=%.2f | w1=%.1f/w2=%.1f",
        settings.wazuh_api_url,
        settings.wazuh_indexer_url,
        settings.db_pool_size,
        settings.decay_factor,
        settings.weight_vulnerability,
        settings.weight_threat,
    )
    return settings
