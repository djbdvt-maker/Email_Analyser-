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


def test_valid_jwt_secret_in_production_passes():
    s = Settings(
        environment="production",
        jwt_secret_key="very-secure-random-token-here-32-chars-long"
    )
    validate_settings(s)


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
