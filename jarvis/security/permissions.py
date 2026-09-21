"""Core types shared by the whole security layer.

Nothing in this file executes anything. It only defines the vocabulary the
policy engine, command validator, tools, and UI use to talk about actions:
what an action is, how risky it is, and what the engine decided to do about
it. Keeping these as plain dataclasses (no behavior) makes the policy engine
the single place that turns "a request" into "a decision".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PermissionLevel(str, Enum):
    """The four categories from the spec, plus DENY for the absolute deny list."""

    READ = "READ"
    SAFE = "SAFE"
    MODIFY = "MODIFY"
    DESTRUCTIVE = "DESTRUCTIVE"
    DENY = "DENY"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    CONFIRM = "CONFIRM"
    DENY = "DENY"


class ApprovalScope(str, Enum):
    ONCE = "once"
    SESSION = "session"
    ALWAYS_THIS_ACTION = "always_this_action"
    DENY = "deny"
    CANCEL = "cancel"


@dataclass
class ActionRequest:
    """A tool call the LLM (or planner) wants to make, before any policy check."""

    tool_name: str
    args: dict[str, Any] = field(default_factory=dict)
    # Free-text description of WHAT/WHY, filled in by the tool for the approval card.
    description: str = ""
    # Absolute paths this action reads or writes, if any -- used for deny-root checks.
    paths: list[str] = field(default_factory=list)
    # Shell command string, only set for terminal tools.
    command: str | None = None
    cwd: str | None = None
    reversible: bool | None = None
    request_id: str = ""
    # Stable key used for "always allow this specific action" grants, e.g.
    # "execute_command:pip_install:project=<path>". Tools set this explicitly
    # rather than letting the engine guess, so grants stay narrow.
    grant_key: str | None = None


@dataclass
class PolicyDecision:
    decision: Decision
    category: PermissionLevel
    risk: RiskLevel
    reasons: list[str] = field(default_factory=list)
    # True only when this exact decision came from the absolute deny list --
    # UI must never offer an override for these.
    absolute: bool = False
