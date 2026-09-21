"""Classifies a shell command string into a PermissionLevel + RiskLevel.

This is allowlist-first: a command is only ever treated as READ/SAFE if it
matches a known-safe prefix. Anything that doesn't match a known safe or
known modify pattern is classified DESTRUCTIVE by default (fail closed),
even if it isn't in the explicit destructive-pattern list. The explicit
destructive patterns exist to get the risk labeling and reasons right for
common cases, not to define the full boundary of "dangerous".
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from jarvis.security.deny_list import denied_command
from jarvis.security.permissions import PermissionLevel, RiskLevel


@dataclass
class CommandClassification:
    category: PermissionLevel
    risk: RiskLevel
    reasons: list[str] = field(default_factory=list)
    denied: bool = False


# Read-only: informational commands with no filesystem/process/network side effects.
_READ_PREFIXES = (
    "git status", "git log", "git diff", "git branch", "git remote", "git show",
    "git rev-parse", "git describe", "git blame",
    "dir", "ls", "pwd", "cd", "type", "cat", "more", "find /i", "where", "which",
    "echo", "whoami", "hostname", "systeminfo", "ver", "python --version",
    "python -V", "python3 --version", "pip --version", "pip list", "pip show",
    "pip freeze", "node --version", "npm --version", "npm list", "npm ls",
    "docker --version", "docker ps", "docker images", "docker info",
    "java -version", "javac -version", "netstat", "tasklist", "get-process",
    "get-childitem", "get-content", "get-location", "env", "set", "printenv",
    "df", "du -sh", "wmic", "systemctl status", "service status",
)

# Modify: changes state but is routine, project-scoped, and reversible in the
# ordinary sense (undo by reinstalling/re-cloning/deleting the new file).
_MODIFY_PREFIXES = (
    "pip install", "pip uninstall", "npm install", "npm uninstall", "npm ci",
    "npm run", "npm build", "yarn install", "yarn add",
    "python -m venv", "python3 -m venv", "virtualenv",
    "git add", "git commit", "git fetch", "git pull", "git checkout -b",
    "git switch -c", "git tag", "git stash",
    "mkdir", "md ", "new-item", "touch", "copy", "cp ", "xcopy", "move ", "mv ",
    "docker build", "docker run", "docker-compose up", "docker compose up",
)

# Destructive: explicit patterns worth naming precisely (for the reason
# string shown to the user) even though the fail-closed default would catch
# most of these anyway.
_DESTRUCTIVE_PATTERNS: tuple[re.Pattern, ...] = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\brm\s+-rf\b", r"\brm\s+-r\b", r"\bremove-item\b.*-recurse",
    r"\bdel\s+/s\b", r"\brd\s+/s\b", r"\brmdir\s+/s\b",
    r"\bformat\s+[a-z]:\b", r"\bdiskpart\b",
    r"\bshutdown\b", r"\brestart-computer\b",
    r"\bgit\s+reset\s+--hard\b", r"\bgit\s+clean\s+-[a-z]*f",
    r"\bgit\s+push\s+.*--force\b", r"\bgit\s+push\s+.*-f\b",
    r"\bdrop\s+(table|database)\b", r"\btruncate\s+table\b",
    r"\btaskkill\b.*\/f\b", r"\bstop-process\b.*-force",
    r"\bnew-itemproperty\b", r"\bset-itemproperty\b",
    r"\bunset\s+.*path\b", r"\bsetx\s+path\b",
    r"\bnpm\s+uninstall\s+-g\b", r"\bpip\s+uninstall\s+-y\s+--all\b",
    r"\bwmic\s+.*delete\b", r"\bicacls\b",
    r"^\s*:\(\)\s*\{.*\}\s*;\s*:",  # fork bomb
))

_SYSTEM_DIR_PATTERN = re.compile(
    r"c:\\windows\b|c:\\program files\b|/etc/|/bin/|/usr/bin", re.IGNORECASE
)


def classify_command(command: str, cwd: str | None = None) -> CommandClassification:
    stripped = command.strip()
    if not stripped:
        return CommandClassification(PermissionLevel.DENY, RiskLevel.CRITICAL, ["Empty command."], denied=True)

    deny_reason = denied_command(stripped)
    if deny_reason:
        return CommandClassification(PermissionLevel.DENY, RiskLevel.CRITICAL, [deny_reason], denied=True)

    lowered = stripped.lower()

    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(lowered):
            return CommandClassification(
                PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH,
                [f"Matches destructive pattern: {pattern.pattern}"],
            )

    if _SYSTEM_DIR_PATTERN.search(lowered) and not lowered.startswith(("dir", "ls", "type", "cat", "echo")):
        return CommandClassification(
            PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH,
            ["Command references a system directory."],
        )

    # Chaining/piping/redirection operators (;, &&, |, `, $(...), >, >>, <) must
    # be checked BEFORE prefix matching below. Otherwise a command like
    # "echo hi > ~/.bashrc" or "dir & npm publish" would match the READ prefix
    # "echo"/"dir" via startswith() and never have its trailing, unverified
    # second half looked at at all.
    if any(sep in stripped for sep in (";", "&&", "||", "|", "`", "$(", ">", "<", "&")):
        return CommandClassification(
            PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH,
            ["Command chains, pipes, or redirects multiple operations; not individually verifiable."],
        )

    try:
        shlex.split(stripped)
    except ValueError:
        return CommandClassification(
            PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH,
            ["Command could not be safely parsed (unbalanced quoting)."],
        )

    for prefix in _READ_PREFIXES:
        if lowered.startswith(prefix):
            return CommandClassification(PermissionLevel.READ, RiskLevel.LOW, [f"Matches read-only prefix '{prefix}'."])

    for prefix in _MODIFY_PREFIXES:
        if lowered.startswith(prefix):
            return CommandClassification(PermissionLevel.MODIFY, RiskLevel.MEDIUM, [f"Matches routine modify prefix '{prefix}'."])

    # Fail closed: unknown command shape, not on any allowlist.
    return CommandClassification(
        PermissionLevel.DESTRUCTIVE, RiskLevel.MEDIUM,
        ["Command does not match a known read-only or routine-modify pattern; treated as high-risk by default."],
    )
