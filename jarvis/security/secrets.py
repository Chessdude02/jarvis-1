"""Deterministic secret detection and redaction.

Per the spec's explicit instruction: "Do not merely rely on the LLM to
recognize secrets. Use deterministic secret scanning." This module is the
single source of truth for what a "secret-shaped" string looks like, used
at every point where content that might contain one gets logged, stored, or
displayed: the audit log (AuditLog.record), local memory (Memory.add_message
/ record_action), and command output before it becomes a tool result (so a
leaked key doesn't reach either the chat UI or the LLM's own context).

This is a best-effort pattern match, not a guarantee -- it catches the
common, recognizable shapes (cloud provider key prefixes, JWTs, PEM key
blocks, "password: ..." style assignments). It is one layer of a defense
that also never grants the LLM credential-store access in the first place.
"""
from __future__ import annotations

import re
from typing import Any

_SECRET_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),                              # OpenAI/Anthropic-style API keys
    re.compile(r"AKIA[0-9A-Z]{16}"),                                  # AWS access key id
    re.compile(r"ghp_[a-zA-Z0-9]{30,}"),                              # GitHub personal access token
    re.compile(r"gho_[a-zA-Z0-9]{30,}"),                              # GitHub OAuth token
    re.compile(r"xox[baprs]-[a-zA-Z0-9-]{10,}"),                      # Slack tokens
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|password|secret|token|access[_-]?key)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    re.compile(r"(?i)(postgres|postgresql|mysql|mongodb|redis)://[^\s'\"]*:[^\s'\"@]*@[^\s'\"]+"),  # DB connection strings with embedded creds
)


def redact(text: str) -> str:
    if not text:
        return text
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def contains_secret(text: str) -> bool:
    return bool(text) and any(p.search(text) for p in _SECRET_PATTERNS)


def redact_value(value: Any) -> Any:
    """Recursively redacts strings inside dicts/lists/tuples; other types
    pass through unchanged. Used to sanitize a whole tool-result/args dict
    (e.g. before writing it to the audit log) without needing every caller
    to know which specific field might contain command output.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(v) for v in value)
    return value
