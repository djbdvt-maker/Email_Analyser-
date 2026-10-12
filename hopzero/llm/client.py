"""
HopZero LLM Client Protocol & Data Types (HZ2).
===============================================

Defines the single unified protocol and response types for all LLM interactions
within HopZero (Forensics Semantic Analyzer and BotChain Tool-Calling).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Union, runtime_checkable

import yaml

# Standard AI Error Constants (Preserving locked spec)
ERR_AI_UNAVAILABLE_TIMEOUT = "AI_UNAVAILABLE_TIMEOUT"
ERR_AI_UNAVAILABLE_CONNECTION_REFUSED = "AI_UNAVAILABLE_CONNECTION_REFUSED"
ERR_AI_UNAVAILABLE_MODEL_NOT_LOADED = "AI_UNAVAILABLE_MODEL_NOT_LOADED"
ERR_AI_UNAVAILABLE_RESOURCE_EXHAUSTED = "AI_UNAVAILABLE_RESOURCE_EXHAUSTED"
ERR_AI_INVALID_JSON = "AI_INVALID_JSON"
ERR_AI_INVALID_SCHEMA = "AI_INVALID_SCHEMA"
ERR_AI_REFUSAL = "AI_REFUSAL"

# Heuristics for detecting LLM refusal strings
REFUSAL_TRIGGERS: tuple[str, ...] = (
    "i cannot fulfill",
    "i am unable to",
    "as an ai",
    "i cannot assist",
    "cannot generate malicious",
    "policy prevents",
    "against my safety guidelines",
    "i cannot generate",
    "i cannot comply",
)


class LLMConfigValidationError(ValueError):
    """Raised when LLM configuration fails schema validation."""
    pass


@dataclass
class LLMConfig:
    """Unified configuration for the shared local LLM."""
    model: str = "hermes3:3b"
    base_url: str = "http://127.0.0.1:11434"
    num_ctx: int = 4096
    temperature: float = 0.0
    seed: int = 42
    keep_alive: str = "5m"
    request_timeout_s: float = 30.0
    max_concurrency: int = 4
    api_key: Optional[str] = None
    timeout_seconds: Optional[float] = None

    def __post_init__(self):
        if self.timeout_seconds is not None:
            self.request_timeout_s = self.timeout_seconds
        else:
            self.timeout_seconds = self.request_timeout_s

    def validate(self) -> None:
        """Validates configuration parameters against schema invariants."""
        if not self.model or not isinstance(self.model, str) or not self.model.strip():
            raise LLMConfigValidationError("LLM 'model' must be a non-empty string.")
        if not self.base_url or not (self.base_url.startswith("http://") or self.base_url.startswith("https://")):
            raise LLMConfigValidationError(f"Invalid 'base_url' '{self.base_url}'. Must start with http:// or https://")
        if not isinstance(self.num_ctx, int) or self.num_ctx <= 0:
            raise LLMConfigValidationError(f"Invalid 'num_ctx' {self.num_ctx}. Must be a positive integer.")
        if not (0.0 <= self.temperature <= 2.0):
            raise LLMConfigValidationError(f"Invalid 'temperature' {self.temperature}. Must be between 0.0 and 2.0.")
        if self.seed < 0:
            raise LLMConfigValidationError(f"Invalid 'seed' {self.seed}. Must be non-negative.")
        if self.request_timeout_s <= 0:
            raise LLMConfigValidationError(f"Invalid 'request_timeout_s' {self.request_timeout_s}. Must be positive.")
        if self.max_concurrency < 1:
            raise LLMConfigValidationError(f"Invalid 'max_concurrency' {self.max_concurrency}. Must be >= 1.")
        if not str(self.keep_alive).strip():
            raise LLMConfigValidationError("Invalid 'keep_alive'. Must be a non-empty string.")

    @classmethod
    def from_yaml(cls, path: Optional[Union[str, Path]] = None) -> LLMConfig:
        """Loads configuration from YAML file, falling back to defaults/env."""
        if path is None:
            default_path = Path(__file__).resolve().parent.parent.parent / "config" / "llm.yaml"
            if default_path.exists():
                path = default_path

        data: Dict[str, Any] = {}
        if path and Path(path).exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        data = loaded
            except Exception as e:
                import logging
                logging.getLogger("hopzero.llm").warning(f"Error reading YAML from {path}: {e}")

        timeout_raw = (
            os.environ.get("HOPZERO_LLM_TIMEOUT_SECONDS")
            or data.get("request_timeout_s")
            or data.get("timeout_seconds", 30.0)
        )

        model = os.environ.get("HOPZERO_LLM_MODEL") or data.get("model", "hermes3:3b")
        base_url = os.environ.get("HOPZERO_LLM_BASE_URL") or data.get("base_url", "http://127.0.0.1:11434")
        num_ctx = int(os.environ.get("HOPZERO_LLM_NUM_CTX") or data.get("num_ctx", 4096))
        temperature = float(os.environ.get("HOPZERO_LLM_TEMPERATURE") or data.get("temperature", 0.0))
        seed = int(os.environ.get("HOPZERO_LLM_SEED") or data.get("seed", 42))
        keep_alive = str(os.environ.get("HOPZERO_LLM_KEEP_ALIVE") or data.get("keep_alive", "5m"))
        request_timeout_s = float(timeout_raw)
        max_concurrency = int(os.environ.get("HOPZERO_LLM_MAX_CONCURRENCY") or data.get("max_concurrency", 4))
        api_key = os.environ.get("HOPZERO_LLM_API_KEY") or data.get("api_key")

        cfg = cls(
            model=model,
            base_url=base_url,
            num_ctx=num_ctx,
            temperature=temperature,
            seed=seed,
            keep_alive=keep_alive,
            request_timeout_s=request_timeout_s,
            max_concurrency=max_concurrency,
            api_key=api_key,
        )
        cfg.validate()
        return cfg


@dataclass
class LLMResponse:
    """Standardized response from any LLMClient implementation."""
    content: str
    parsed: Optional[Any] = None
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    model: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    error: Optional[str] = None
    refusal: bool = False

    @property
    def is_success(self) -> bool:
        """Returns True if the call succeeded without error or refusal."""
        return self.error is None and not self.refusal


@runtime_checkable
class LLMClient(Protocol):
    """Protocol for HopZero LLM interactions."""

    def complete(
        self,
        prompt: str,
        json_schema: Optional[Dict[str, Any]] = None,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        seed: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> LLMResponse:
        ...

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        seed: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> LLMResponse:
        ...
