"""
Central application configuration.

All values are sourced from environment variables (see .env.example).
Nothing here encodes scoring, floors, or forensic logic -- this module
is strictly infrastructure/config.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./storage/hopzero.db"
    test_database_url: str = "sqlite:///./test.db"

    jwt_secret_key: str = "change-me-in-production-hopzero-secure-dev-key-32chars"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    artifact_storage_root: str = "./storage/artifacts"

    # Trusted credentials: NO DEFAULT VALUES ON PURPOSE -- no fallback secret
    # baked into source code. Both keys fail closed if unset.
    hopzero_internal_service_key: str | None = None
    hopzero_n8n_ingest_key: str | None = None
    hopzero_rapidapi_key: str | None = None
    hopzero_api_key: str | None = None
    
    enforcement_provider: str = "mock"  # "mock" | "windows_defender"

    # AI Reasoner / LLM Provider Configuration
    hopzero_llm_provider: str = "offline_deterministic_fallback"  # "ollama" | "openai" | "offline_deterministic_fallback"
    hopzero_llm_base_url: str | None = "http://localhost:11434"  # e.g. "http://localhost:11434" or "http://localhost:8000/v1"
    hopzero_llm_model: str = "hermes3:3b"
    hopzero_llm_api_key: str | None = None
    hopzero_llm_timeout_seconds: float = 30.0

    # Laya Pre-Screen Configuration
    laya_prescreen_enabled: bool = False  # Master toggle for the Laya pre-screening layer
    laya_prescreen_model: str | None = None  # Override: "english", "multilingual", "typed-decisions", or None for auto-routing
    laya_prescreen_skip_ai_on_benign: bool = False  # Safe by default: false to avoid skipping LLM on semantic threats (F5)
    laya_prescreen_benign_confidence_threshold: float = 0.75  # Minimum confidence to trust a benign classification for AI skip

    # Sandbox Screenshot Configuration (SSRF Hardened, F4)
    sandbox_screenshot_enabled: bool = False  # Off by default in Lite/Standard (requires explicit setting)
    sandbox_timeout_seconds: float = 10.0
    sandbox_max_redirects: int = 5

    # Parser Isolation Configuration
    parser_isolation_mode: str = "subprocess"  # "subprocess" | "process_pool" | "in_process"
    parser_timeout_seconds: float = 15.0

    cors_origins: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"
    public_url: str | None = None
    environment: str = "development"


import logging
import secrets
from pathlib import Path

logger = logging.getLogger("hopzero.config")

INSECURE_SECRET_PLACEHOLDERS = {
    "change-me-in-production",
    "change-me-in-production-hopzero-secure-dev-key-32chars",
    "secret",
    "password",
    "default",
    "changeme",
    "admin",
    "12345678",
    "demo",
    "test",
    "sih-extension-demo-key",
    "dev-secret",
    "supersecret",
}


class ConfigurationError(RuntimeError):
    """Raised when an environment or startup configuration invariant fails."""
    def __init__(self, message: str, hint: str = ""):
        self.message = message
        self.hint = hint
        formatted = f"\n[CONFIGURATION ERROR] {message}"
        if hint:
            formatted += f"\n  --> HINT: {hint}"
        super().__init__(formatted)


def validate_settings(settings: Settings) -> None:
    """
    Validates application settings at startup with readable, actionable errors.
    Fails closed before sockets or database pools open.
    """
    # 1. Database URL scheme validation
    valid_db_prefixes = ("sqlite:///", "sqlite:", "postgresql://", "postgresql+psycopg2://")
    if not any(settings.database_url.startswith(prefix) for prefix in valid_db_prefixes):
        raise ConfigurationError(
            f"Invalid DATABASE_URL scheme '{settings.database_url.split('://')[0] if '://' in settings.database_url else settings.database_url}'.",
            "Set DATABASE_URL to a valid SQLite ('sqlite:///./storage/hopzero.db') or PostgreSQL URI ('postgresql+psycopg2://user:pass@localhost:5432/hopzero')."
        )

    # 2. Production secrets & insecure defaults validation (F8)
    if settings.environment.lower() == "production":
        jwt_key = settings.jwt_secret_key.strip() if settings.jwt_secret_key else ""
        if not jwt_key or jwt_key.lower() in INSECURE_SECRET_PLACEHOLDERS:
            raise ConfigurationError(
                "Insecure default or empty JWT_SECRET_KEY in production mode.",
                'Generate a cryptographically secure key with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )
        if len(jwt_key) < 32:
            raise ConfigurationError(
                f"JWT_SECRET_KEY in production mode must be at least 32 characters (got {len(jwt_key)}).",
                'Generate a cryptographically secure key with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )

        # Deny placeholder API and service keys in production
        for key_name, val in [
            ("HOPZERO_API_KEY", settings.hopzero_api_key),
            ("HOPZERO_INTERNAL_SERVICE_KEY", settings.hopzero_internal_service_key),
            ("HOPZERO_N8N_INGEST_KEY", settings.hopzero_n8n_ingest_key),
        ]:
            if val and val.strip().lower() in INSECURE_SECRET_PLACEHOLDERS:
                raise ConfigurationError(
                    f"Insecure placeholder value detected for {key_name} in production mode: '{val}'.",
                    f"Set a strong, unique secret key for {key_name} or leave it unset."
                )
    else:
        # Development / test mode warning
        jwt_key = settings.jwt_secret_key.strip() if settings.jwt_secret_key else ""
        if not jwt_key:
            settings.jwt_secret_key = secrets.token_urlsafe(32)
            logger.warning("[SECURITY WARNING] No JWT_SECRET_KEY provided in development; generated ephemeral key.")
        elif jwt_key.lower() in INSECURE_SECRET_PLACEHOLDERS:
            logger.warning(
                "[SECURITY WARNING] Using default/insecure JWT_SECRET_KEY in development mode. "
                "In production, startup will fail unless a strong key (>= 32 chars) is set."
            )

    # 3. Parser isolation mode validation
    valid_isolation_modes = {"subprocess", "process_pool", "in_process"}
    if settings.parser_isolation_mode not in valid_isolation_modes:
        raise ConfigurationError(
            f"Invalid PARSER_ISOLATION_MODE '{settings.parser_isolation_mode}'.",
            f"Valid options are: {', '.join(sorted(valid_isolation_modes))}."
        )

    # 4. LLM provider validation
    valid_llm_providers = {"ollama", "openai", "offline_deterministic_fallback"}
    if settings.hopzero_llm_provider not in valid_llm_providers:
        raise ConfigurationError(
            f"Invalid HOPZERO_LLM_PROVIDER '{settings.hopzero_llm_provider}'.",
            f"Valid options are: {', '.join(sorted(valid_llm_providers))}."
        )

    # 5. Artifact storage root validation
    try:
        p = Path(settings.artifact_storage_root)
        p.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        raise ConfigurationError(
            f"Cannot create or access ARTIFACT_STORAGE_ROOT at '{settings.artifact_storage_root}': {e}",
            "Ensure the directory path is writable or set ARTIFACT_STORAGE_ROOT in your .env."
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()

