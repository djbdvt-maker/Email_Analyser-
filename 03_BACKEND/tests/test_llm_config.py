"""
03_BACKEND/tests/test_llm_config.py
Tests for F10: config/llm.yaml schema validation, environment overrides, and reload prevention.
"""
import os
import pytest
from pathlib import Path
from hopzero.llm.client import LLMConfig, LLMConfigValidationError


def test_load_default_llm_yaml():
    cfg = LLMConfig.from_yaml()
    assert cfg.model == "hermes3:3b"
    assert cfg.base_url.startswith("http://")
    assert cfg.num_ctx == 4096
    assert cfg.keep_alive == "5m"
    assert cfg.temperature == 0.0
    assert cfg.seed == 42
    assert cfg.request_timeout_s == 30.0
    assert cfg.timeout_seconds == 30.0
    assert cfg.max_concurrency == 4


def test_validation_rejects_empty_model():
    cfg = LLMConfig(model="")
    with pytest.raises(LLMConfigValidationError) as exc:
        cfg.validate()
    assert "model" in str(exc.value)


def test_validation_rejects_invalid_base_url():
    cfg = LLMConfig(base_url="ftp://localhost:11434")
    with pytest.raises(LLMConfigValidationError) as exc:
        cfg.validate()
    assert "base_url" in str(exc.value)


def test_validation_rejects_invalid_num_ctx():
    cfg = LLMConfig(num_ctx=-10)
    with pytest.raises(LLMConfigValidationError) as exc:
        cfg.validate()
    assert "num_ctx" in str(exc.value)


def test_validation_rejects_invalid_temperature():
    cfg = LLMConfig(temperature=5.0)
    with pytest.raises(LLMConfigValidationError) as exc:
        cfg.validate()
    assert "temperature" in str(exc.value)


def test_validation_rejects_negative_seed():
    cfg = LLMConfig(seed=-1)
    with pytest.raises(LLMConfigValidationError) as exc:
        cfg.validate()
    assert "seed" in str(exc.value)


def test_validation_rejects_zero_timeout():
    cfg = LLMConfig(request_timeout_s=0.0)
    with pytest.raises(LLMConfigValidationError) as exc:
        cfg.validate()
    assert "request_timeout_s" in str(exc.value)


def test_env_override(monkeypatch):
    monkeypatch.setenv("HOPZERO_LLM_MODEL", "custom-model:7b")
    monkeypatch.setenv("HOPZERO_LLM_TEMPERATURE", "0.7")
    monkeypatch.setenv("HOPZERO_LLM_NUM_CTX", "8192")
    cfg = LLMConfig.from_yaml()
    assert cfg.model == "custom-model:7b"
    assert cfg.temperature == 0.7
    assert cfg.num_ctx == 8192


def test_consecutive_calls_preserve_consistent_options_hash():
    """
    Verifies that multiple calls construct identical option dictionaries,
    guaranteeing that alternating requests do not trigger model reload in Ollama.
    """
    cfg1 = LLMConfig.from_yaml()
    cfg2 = LLMConfig.from_yaml()

    options1 = {
        "num_ctx": cfg1.num_ctx,
        "temperature": cfg1.temperature,
        "seed": cfg1.seed,
    }
    options2 = {
        "num_ctx": cfg2.num_ctx,
        "temperature": cfg2.temperature,
        "seed": cfg2.seed,
    }

    assert options1 == options2
    assert cfg1.model == cfg2.model
    assert cfg1.keep_alive == cfg2.keep_alive
