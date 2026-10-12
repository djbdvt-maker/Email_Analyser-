"""
03_BACKEND/tests/test_settings_validation.py
Tests for startup configuration validation and readable error messages.
"""
import pytest
from app.config import Settings, validate_settings, ConfigurationError


def test_valid_default_settings():
    s = Settings()
    # Default settings must validate without error
    validate_settings(s)


def test_invalid_database_url_raises_readable_error():
    s = Settings(database_url="mysql://root:pass@localhost:3306/hopzero")
    with pytest.raises(ConfigurationError) as exc_info:
        validate_settings(s)
    err = str(exc_info.value)
    assert "Invalid DATABASE_URL scheme" in err
    assert "HINT:" in err
    assert "sqlite:///" in err or "postgresql" in err


def test_insecure_jwt_secret_in_production_raises_readable_error():
    s = Settings(
        environment="production",
        jwt_secret_key="change-me-in-production"
    )
    with pytest.raises(ConfigurationError) as exc_info:
        validate_settings(s)
    err = str(exc_info.value)
    assert "Insecure default or empty JWT_SECRET_KEY in production mode" in err
    assert "HINT:" in err
    assert "secrets.token_urlsafe" in err


def test_short_jwt_secret_in_production_raises():
    s = Settings(
        environment="production",
        jwt_secret_key="short-secret-under-32-chars"
    )
    with pytest.raises(ConfigurationError) as exc_info:
        validate_settings(s)
    err = str(exc_info.value)
    assert "at least 32 characters" in err


def test_placeholder_api_key_in_production_raises():
    s = Settings(
        environment="production",
        jwt_secret_key="very-secure-random-token-here-32-chars-long",
        hopzero_api_key="sih-extension-demo-key"
    )
    with pytest.raises(ConfigurationError) as exc_info:
        validate_settings(s)
    err = str(exc_info.value)
    assert "Insecure placeholder value detected for HOPZERO_API_KEY in production mode" in err


def test_placeholder_internal_key_in_production_raises():
    s = Settings(
        environment="production",
        jwt_secret_key="very-secure-random-token-here-32-chars-long",
        hopzero_internal_service_key="change-me-in-production"
    )
    with pytest.raises(ConfigurationError) as exc_info:
        validate_settings(s)
    err = str(exc_info.value)
    assert "Insecure placeholder value detected for HOPZERO_INTERNAL_SERVICE_KEY in production mode" in err


def test_placeholder_n8n_key_in_production_raises():
    s = Settings(
        environment="production",
        jwt_secret_key="very-secure-random-token-here-32-chars-long",
        hopzero_n8n_ingest_key="password"
    )
    with pytest.raises(ConfigurationError) as exc_info:
        validate_settings(s)
    err = str(exc_info.value)
    assert "Insecure placeholder value detected for HOPZERO_N8N_INGEST_KEY in production mode" in err


def test_valid_jwt_secret_in_production_passes():
    s = Settings(
        environment="production",
        jwt_secret_key="very-secure-random-token-here-32-chars-long",
        hopzero_api_key="custom-production-api-key-that-is-not-a-placeholder"
    )
    validate_settings(s)


def test_development_mode_allows_default_with_warning(caplog):
    s = Settings(
        environment="development",
        jwt_secret_key="change-me-in-production"
    )
    validate_settings(s)
    assert any("Using default/insecure JWT_SECRET_KEY in development mode" in record.message for record in caplog.records)


def test_development_mode_generates_ephemeral_key_if_empty(caplog):
    s = Settings(
        environment="development",
        jwt_secret_key=""
    )
    validate_settings(s)
    assert len(s.jwt_secret_key) >= 32
    assert any("generated ephemeral key" in record.message for record in caplog.records)


def test_invalid_parser_isolation_mode_raises():
    s = Settings(parser_isolation_mode="unsafe_eval")
    with pytest.raises(ConfigurationError) as exc_info:
        validate_settings(s)
    err = str(exc_info.value)
    assert "Invalid PARSER_ISOLATION_MODE" in err
    assert "subprocess" in err


def test_invalid_llm_provider_raises():
    s = Settings(hopzero_llm_provider="cloud_unknown")
    with pytest.raises(ConfigurationError) as exc_info:
        validate_settings(s)
    err = str(exc_info.value)
    assert "Invalid HOPZERO_LLM_PROVIDER" in err
    assert "ollama" in err
