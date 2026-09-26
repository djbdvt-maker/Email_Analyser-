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

    database_url: str = "postgresql+psycopg2://hopzero:hopzero@localhost:5432/hopzero"
    test_database_url: str = "sqlite:///./test.db"

    jwt_secret_key: str = "change-me-in-production"
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
    hopzero_llm_model: str = "phi3"
    hopzero_llm_api_key: str | None = None
    hopzero_llm_timeout_seconds: float = 30.0

    # Laya Pre-Screen Configuration
    laya_prescreen_enabled: bool = False  # Master toggle for the Laya pre-screening layer
    laya_prescreen_model: str | None = None  # Override: "english", "multilingual", "typed-decisions", or None for auto-routing
    laya_prescreen_skip_ai_on_benign: bool = True  # Skip expensive LLM call when Laya classifies as benign with high confidence
    laya_prescreen_benign_confidence_threshold: float = 0.75  # Minimum confidence to trust a benign classification for AI skip

    cors_origins: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"
    environment: str = "development"


@lru_cache
def get_settings() -> Settings:
    return Settings()
