"""
Ollama Local LLM Adapter (HZ2).
===============================

Implements LLMClient against a local Ollama instance hosting a single resident
model (hermes3:3b) shared between Forensics Semantic Analysis and BotChain Tool Calling.
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .client import (
    ERR_AI_INVALID_JSON,
    ERR_AI_INVALID_SCHEMA,
    ERR_AI_REFUSAL,
    ERR_AI_UNAVAILABLE_CONNECTION_REFUSED,
    ERR_AI_UNAVAILABLE_MODEL_NOT_LOADED,
    ERR_AI_UNAVAILABLE_RESOURCE_EXHAUSTED,
    ERR_AI_UNAVAILABLE_TIMEOUT,
    REFUSAL_TRIGGERS,
    LLMClient,
    LLMConfig,
    LLMResponse,
)

logger = logging.getLogger("hopzero.llm.ollama")


class OllamaLLMClient(LLMClient):
    """
    Ollama implementation of LLMClient.
    Enforces keep_alive to keep the selected single model resident in VRAM.
    """

    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        self.config = config or LLMConfig.from_yaml()

    def _post(self, endpoint: str, payload: Dict[str, Any], timeout: float) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        url = f"{self.config.base_url.rstrip('/')}{endpoint}"
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_bytes = resp.read().decode("utf-8")
                return json.loads(resp_bytes), None
        except urllib.error.HTTPError as e:
            logger.warning(f"Ollama HTTP error {e.code}: {e.reason}")
            if e.code == 429:
                return None, ERR_AI_UNAVAILABLE_RESOURCE_EXHAUSTED
            elif e.code in (404, 400):
                return None, ERR_AI_UNAVAILABLE_MODEL_NOT_LOADED
            return None, ERR_AI_UNAVAILABLE_CONNECTION_REFUSED
        except urllib.error.URLError as e:
            logger.warning(f"Ollama connection error: {e.reason}")
            return None, ERR_AI_UNAVAILABLE_CONNECTION_REFUSED
        except TimeoutError:
            logger.warning("Ollama request timed out")
            return None, ERR_AI_UNAVAILABLE_TIMEOUT
        except Exception as e:
            logger.warning(f"Unexpected error calling Ollama: {e}")
            return None, ERR_AI_UNAVAILABLE_CONNECTION_REFUSED

    def _check_refusal(self, content: str) -> bool:
        lower = content.strip().lower()
        if not lower:
            return False
        for trigger in REFUSAL_TRIGGERS:
            if trigger in lower:
                return True
        return False

    def complete(
        self,
        prompt: str,
        json_schema: Optional[Dict[str, Any]] = None,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        seed: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> LLMResponse:
        t0 = time.perf_counter()
        call_timeout = timeout if timeout is not None else self.config.timeout_seconds
        temp = temperature if temperature is not None else self.config.temperature
        s = seed if seed is not None else self.config.seed

        payload: Dict[str, Any] = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": self.config.keep_alive,
            "options": {
                "temperature": temp,
                "seed": s,
                "num_ctx": self.config.num_ctx,
            },
        }
        if system:
            payload["system"] = system
        if json_schema is not None:
            payload["format"] = json_schema

        raw_json, error_code = self._post("/api/generate", payload, timeout=call_timeout)
        duration_ms = (time.perf_counter() - t0) * 1000.0

        if error_code:
            return LLMResponse(
                content="",
                model=self.config.model,
                duration_ms=duration_ms,
                error=error_code,
            )

        content = raw_json.get("response", "") if raw_json else ""

        if self._check_refusal(content):
            return LLMResponse(
                content=content,
                model=self.config.model,
                raw=raw_json or {},
                duration_ms=duration_ms,
                error=ERR_AI_REFUSAL,
                refusal=True,
            )

        parsed = None
        if json_schema is not None:
            clean_text = content.strip()
            if clean_text.startswith("```"):
                clean_text = re.sub(r"^```(?:json)?\s*", "", clean_text)
                clean_text = re.sub(r"\s*```$", "", clean_text)
            try:
                parsed = json.loads(clean_text)
            except json.JSONDecodeError:
                return LLMResponse(
                    content=content,
                    model=self.config.model,
                    raw=raw_json or {},
                    duration_ms=duration_ms,
                    error=ERR_AI_INVALID_JSON,
                )

        return LLMResponse(
            content=content,
            parsed=parsed,
            model=self.config.model,
            raw=raw_json or {},
            duration_ms=duration_ms,
        )

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        seed: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> LLMResponse:
        t0 = time.perf_counter()
        call_timeout = timeout if timeout is not None else self.config.timeout_seconds
        temp = temperature if temperature is not None else self.config.temperature
        s = seed if seed is not None else self.config.seed

        formatted_messages = list(messages)
        if system and not any(m.get("role") == "system" for m in formatted_messages):
            formatted_messages = [{"role": "system", "content": system}] + formatted_messages

        payload: Dict[str, Any] = {
            "model": self.config.model,
            "messages": formatted_messages,
            "stream": False,
            "keep_alive": self.config.keep_alive,
            "options": {
                "temperature": temp,
                "seed": s,
                "num_ctx": self.config.num_ctx,
            },
        }
        if tools:
            payload["tools"] = tools

        raw_json, error_code = self._post("/api/chat", payload, timeout=call_timeout)
        duration_ms = (time.perf_counter() - t0) * 1000.0

        if error_code:
            return LLMResponse(
                content="",
                model=self.config.model,
                duration_ms=duration_ms,
                error=error_code,
            )

        msg = raw_json.get("message", {}) if raw_json else {}
        content = msg.get("content", "")
        raw_tool_calls = msg.get("tool_calls", [])

        if not raw_tool_calls and tools and content:
            raw_tool_calls = self._extract_tool_calls_from_content(content)

        if self._check_refusal(content):
            return LLMResponse(
                content=content,
                model=self.config.model,
                raw=raw_json or {},
                duration_ms=duration_ms,
                error=ERR_AI_REFUSAL,
                refusal=True,
            )

        return LLMResponse(
            content=content,
            tool_calls=raw_tool_calls,
            model=self.config.model,
            raw=raw_json or {},
            duration_ms=duration_ms,
        )

    def _extract_tool_calls_from_content(self, content: str) -> List[Dict[str, Any]]:
        tool_calls: List[Dict[str, Any]] = []
        if not content:
            return tool_calls

        for m in re.finditer(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", content, re.DOTALL):
            try:
                data = json.loads(m.group(1))
                if "name" in data:
                    tool_calls.append({
                        "function": {
                            "name": data["name"],
                            "arguments": data.get("arguments", {}),
                        }
                    })
            except Exception:
                pass
        if tool_calls:
            return tool_calls

        clean = content.strip().lstrip(",").strip()
        try:
            obj = json.loads(clean)
            if isinstance(obj, dict) and "name" in obj:
                return [{
                    "function": {
                        "name": obj["name"],
                        "arguments": obj.get("arguments", {}),
                    }
                }]
        except Exception:
            pass

        for m in re.finditer(r"\{[^{}]*\"name\"\s*:\s*\"([^\"]+)\"[^{}]*\}", content, re.DOTALL):
            try:
                data = json.loads(m.group(0))
                tool_calls.append({
                    "function": {
                        "name": data["name"],
                        "arguments": data.get("arguments", {}),
                    }
                })
            except Exception:
                tool_calls.append({
                    "function": {
                        "name": m.group(1),
                        "arguments": {},
                    }
                })

        return tool_calls
