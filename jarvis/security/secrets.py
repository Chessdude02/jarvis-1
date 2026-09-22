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

# Strips ANSI/terminal escape sequences (CSI color/cursor codes, OSC window-
# title codes, and the simpler single-character escapes) before any secret
# pattern runs. Two reasons: command output routinely carries these from
# colorized build-tool/CLI output, so stripping them keeps the audit log
# and chat display readable either way; and, found by testing, a secret
# with an escape sequence inserted mid-string ("sk-abc\x1b[0mdefghi...")
# evaded every character-class-based pattern below the same way a
# backslash or empty-quote pair evaded the attack-tool deny patterns --
# the character run is broken at the codepoint level even though a real
# terminal would render it as one contiguous, unstyled string.
_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-9;?]*[a-zA-Z]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[()][A-Za-z0-9]|[@-Z\\-_])")

_SECRET_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),                              # OpenAI/Anthropic-style API keys
    re.compile(r"sk_(live|test)_[a-zA-Z0-9]{16,}"),                   # Stripe secret keys (underscore, not hyphen -- found by testing: the sk- pattern above requires a literal hyphen and never matched these)
    re.compile(r"(?:pk|rk)_(live|test)_[a-zA-Z0-9]{16,}"),            # Stripe publishable/restricted keys
    re.compile(r"AKIA[0-9A-Z]{16}"),                                  # AWS access key id
    re.compile(r"ghp_[a-zA-Z0-9]{30,}"),                              # GitHub personal access token
    re.compile(r"gho_[a-zA-Z0-9]{30,}"),                              # GitHub OAuth token
    re.compile(r"xox[baprs]-[a-zA-Z0-9-]{10,}"),                      # Slack tokens
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    # [\w-]* between the keyword and the separator -- found by testing:
    # requiring the separator immediately after the keyword missed the
    # overwhelmingly common env-var/config shape where the keyword is only
    # part of a longer identifier ("MY_API_KEY_VALUE=...",
    # "the_token_variable_name_is: ..." -- "token" is a substring of the
    # identifier, joined to the rest by underscores, which are \w).
    re.compile(r"(?i)(api[_-]?key|password|secret|token|access[_-]?key)[\w-]*\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    re.compile(r"(?i)(postgres|postgresql|mysql|mongodb|redis)://[^\s'\"]*:[^\s'\"@]*@[^\s'\"]+"),  # DB connection strings with embedded creds
)


def redact(text: str) -> str:
    if not text:
        return text
    text = _ANSI_ESCAPE.sub("", text)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def contains_secret(text: str) -> bool:
    if not text:
        return False
    text = _ANSI_ESCAPE.sub("", text)
    return any(p.search(text) for p in _SECRET_PATTERNS)


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
