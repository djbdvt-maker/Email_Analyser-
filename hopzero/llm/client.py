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


@dataclass
class LLMConfig:
    """Unified configuration for the shared local LLM."""
    model: str = "hermes3:3b"
    base_url: str = "http://127.0.0.1:11434"
    num_ctx: int = 4096
    temperature: float = 0.0
    seed: int = 42
    keep_alive: str = "5m"
    timeout_seconds: float = 30.0
    api_key: Optional[str] = None

    @classmethod
    def from_yaml(cls, path: Optional[Union[str, Path]] = None) -> LLMConfig:
        """Loads configuration from YAML file, falling back to defaults/env."""
        if path is None:
            default_path = Path(__file__).resolve().parent.parent.parent / "config" / "llm.yaml"
            if default_path.exists():
                path = default_path

        data: Dict[str, Any] = {}
        if path and Path(path).exists():
            with open(path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    data = loaded

        model = os.environ.get("HOPZERO_LLM_MODEL") or data.get("model", "hermes3:3b")
        base_url = os.environ.get("HOPZERO_LLM_BASE_URL") or data.get("base_url", "http://127.0.0.1:11434")
        num_ctx = int(os.environ.get("HOPZERO_LLM_NUM_CTX") or data.get("num_ctx", 4096))
        temperature = float(os.environ.get("HOPZERO_LLM_TEMPERATURE") or data.get("temperature", 0.0))
        seed = int(os.environ.get("HOPZERO_LLM_SEED") or data.get("seed", 42))
        keep_alive = os.environ.get("HOPZERO_LLM_KEEP_ALIVE") or data.get("keep_alive", "5m")
        timeout_seconds = float(os.environ.get("HOPZERO_LLM_TIMEOUT_SECONDS") or data.get("timeout_seconds", 30.0))
        api_key = os.environ.get("HOPZERO_LLM_API_KEY") or data.get("api_key")

        return cls(
            model=model,
            base_url=base_url,
            num_ctx=num_ctx,
            temperature=temperature,
            seed=seed,
            keep_alive=keep_alive,
            timeout_seconds=timeout_seconds,
            api_key=api_key,
        )


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
