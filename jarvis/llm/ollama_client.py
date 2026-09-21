"""Thin client for a local Ollama server. This is the ONLY network call JARVIS
core functionality makes, and it is hardcoded to settings.llm_host (default
127.0.0.1) -- there is no code path from here to any other host. The
separate, opt-in "online information" feature described in a later phase is
a different module entirely and is never reachable through this client.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterator

import requests


class OllamaUnavailableError(RuntimeError):
    pass


def _normalize_arguments(raw: Any) -> dict[str, Any]:
    """Guarantees ToolCall.arguments is always a dict, regardless of what a
    given model actually returns. Most tool-calling models return an already
    -parsed JSON object here, but some (especially smaller local models)
    return the arguments as a raw JSON string, or omit them, or return
    something malformed entirely -- and every downstream consumer
    (Tool.build_request, Tool.execute) does plain dict-style access with no
    type check of its own. Without normalizing here, a model's formatting
    quirk becomes an uncaught AttributeError deep in the orchestrator loop.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ChatResponse:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


class OllamaClient:
    def __init__(self, settings) -> None:
        self.settings = settings
        self.host = settings.llm_host.rstrip("/")
        self.model = settings.llm_model
        self.timeout = settings.llm_request_timeout_seconds

    def is_available(self) -> bool:
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=3)
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def has_model(self) -> bool:
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=3)
            resp.raise_for_status()
            names = {m.get("name", "").split(":")[0] for m in resp.json().get("models", [])}
            return self.model.split(":")[0] in names
        except requests.RequestException:
            return False

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> ChatResponse:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.settings.llm_temperature},
        }
        if tools:
            payload["tools"] = tools
        try:
            resp = requests.post(f"{self.host}/api/chat", json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise OllamaUnavailableError(
                f"Could not reach local Ollama server at {self.host}: {exc}. "
                f"Is Ollama running ('ollama serve') and is '{self.model}' pulled?"
            ) from exc

        body = resp.json()
        message = body.get("message", {})
        tool_calls = []
        for i, tc in enumerate(message.get("tool_calls", []) or []):
            fn = tc.get("function", {})
            tool_calls.append(ToolCall(id=str(tc.get("id", i)), name=fn.get("name", ""), arguments=_normalize_arguments(fn.get("arguments"))))
        return ChatResponse(content=message.get("content", "") or "", tool_calls=tool_calls, raw=body)

    def chat_stream(self, messages: list[dict]) -> Iterator[str]:
        """Streams plain-text token chunks for a final (no-tools) answer, so
        the UI can show incremental output while THINKING/SUCCESS states hold.
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {"temperature": self.settings.llm_temperature},
        }
        try:
            with requests.post(f"{self.host}/api/chat", json=payload, timeout=self.timeout, stream=True) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line:
                        continue
                    import json as _json
                    chunk = _json.loads(line)
                    piece = chunk.get("message", {}).get("content", "")
                    if piece:
                        yield piece
                    if chunk.get("done"):
                        break
        except requests.RequestException as exc:
            raise OllamaUnavailableError(f"Could not reach local Ollama server at {self.host}: {exc}") from exc
