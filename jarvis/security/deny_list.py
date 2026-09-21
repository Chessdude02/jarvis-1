"""The absolute deny list.

Everything in this file is checked BEFORE any other policy logic and cannot
be overridden by a grant, an "always allow" approval, a config change made
through the app, or anything the LLM says. It is deliberately dumb, static,
pattern-based code -- there is no reasoning step here for the LLM to talk its
way around.

Two kinds of things are denied:
  1. Whole tool/capability names JARVIS must never expose as executable,
     no matter the arguments (disabling AV, reading browser cookies, ...).
  2. Patterns inside otherwise-generic tools (a shell command, a file path)
     that indicate the same prohibited categories.
"""
from __future__ import annotations

import re

# --- 1. Tool names that are never callable, regardless of arguments. ---------
# These are not implemented anywhere in jarvis/tools/ on purpose. The set
# also exists so that if a future tool is ever added with one of these names
# (by mistake, or by a compromised update), the policy engine still refuses
# it deterministically instead of relying on it simply not existing.
ABSOLUTE_DENY_TOOLS: frozenset[str] = frozenset({
    "disable_antivirus",
    "disable_windows_defender",
    "disable_firewall",
    "bypass_uac",
    "disable_security_control",
    "read_browser_cookies",
    "read_password_manager",
    "read_saved_passwords",
    "read_ssh_private_key",
    "read_auth_tokens",
    "exfiltrate_credentials",
    "install_persistence",
    "create_hidden_persistence",
    "modify_boot_configuration",
    "modify_security_policy",
    "grant_admin_privileges",
    "elevate_privileges",
    "hide_activity",
    "hide_process",
    "clear_audit_log",
    "modify_audit_log",
    "delete_audit_log",
    "modify_own_policy",
    "modify_permission_system",
    "disable_logging",
    "self_update_executable",
})

# --- 2. Path fragments that mean "credential / security-sensitive area". ----
# Matched case-insensitively as substrings of a resolved absolute path.
DENY_PATH_FRAGMENTS: tuple[str, ...] = (
    "\\.ssh", "/.ssh",
    "\\.aws", "/.aws",
    "\\.gnupg", "/.gnupg", "\\gnupg",
    "id_rsa", "id_ed25519", "id_ecdsa",
    "\\credentials\\", "/credentials/",
    "\\microsoft\\credentials", "microsoft\\protect",
    "\\google\\chrome\\user data", "/google/chrome/",
    "\\mozilla\\firefox\\profiles", "/mozilla/firefox/",
    "\\microsoft\\edge\\user data",
    "cookies.sqlite", "login data",  # Firefox cookies DB, Chrome "Login Data" DB
    "\\keepass", "/keepass", ".kdbx",
    "\\lastpass", "\\1password", "1password.sqlite",
    "netskope", "\\authy",
    ".npmrc", ".pypirc",  # commonly hold registry auth tokens
    "\\windows\\system32\\config",  # SAM/SYSTEM hives
)

# --- 3. Shell-command patterns that mean a denied category, independent of --
# the command-risk classifier in command_validator.py (which handles the
# broader MODIFY/DESTRUCTIVE spectrum). Anything matching here is an
# outright DENY, not a "confirm".
DENY_COMMAND_PATTERNS: tuple[re.Pattern, ...] = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\bnet\s+stop\s+(windefend|mpsvc|wuauserv)\b",
    r"set-mppreference\s+.*-disable",
    r"\bnetsh\s+advfirewall\s+set\b.*\boff\b",
    r"\bnetsh\s+firewall\s+set\s+opmode\b",
    r"\bnew-itemproperty\b.*\\policies\\",
    r"\breg(\.exe)?\s+add\b.*\\policies\\",
    r"\bicacls\b.*\/grant.*everyone",
    r"\brunas\b.*\/user:administrator",
    r"\bdisable-uac\b|\benable-lua.*0\b",
    r"\bcredentialmanager\b|\bcmdkey\s+/list\b",
    r"\bvssadmin\s+delete\s+shadows\b",
    r"\bwevtutil\s+cl\b",  # clear event log
    r"\bClear-EventLog\b",
    r"\bbcdedit\b",
    r"\breg\s+(export|save)\b.*\\sam\b",
    r"curl[^|]*\|\s*(bash|sh|powershell|iex)\b",
    r"wget[^|]*\|\s*(bash|sh)\b",
    r"invoke-webrequest.*\|\s*iex\b",
    r"-enc(odedcommand)?\s+[a-z0-9+/=]{40,}",  # obfuscated/base64 PowerShell
))


# PowerShell (backtick) and cmd.exe (caret) both support a literal line-
# continuation character immediately before a newline, which is NOT a
# whitespace character itself -- so a pattern written as `\bnet\s+stop\s+
# windefend\b` does not match "net stop`\nwindefend" or "net stop^\r\n
# windefend" even though that is functionally the exact same command a
# real shell would run as one line. Found by testing evasions against the
# Defender-disable and curl|bash patterns specifically, but this collapses
# the continuation before ANY pattern match runs (deny list, destructive
# patterns, chain-separator detection), closing the technique for all of
# them at once rather than patching each affected regex individually.
_LINE_CONTINUATION = re.compile(r"[`^]\s*\r?\n")


def normalize_command(command: str) -> str:
    return _LINE_CONTINUATION.sub(" ", command)


def denied_tool(tool_name: str) -> str | None:
    if tool_name in ABSOLUTE_DENY_TOOLS:
        return f"'{tool_name}' is on the absolute deny list and is never executable."
    return None


def denied_path(path: str) -> str | None:
    lowered = path.replace("/", "\\").lower()
    posix_lowered = path.lower()
    for frag in DENY_PATH_FRAGMENTS:
        f = frag.lower()
        if f in lowered or f in posix_lowered:
            return f"Path touches a credential/security-sensitive location ({frag})."
    return None


def denied_command(command: str) -> str | None:
    normalized = normalize_command(command)
    for pattern in DENY_COMMAND_PATTERNS:
        if pattern.search(normalized):
            return f"Command matches a denied security-control pattern ({pattern.pattern})."
    return None


def denied_system_root(path: str, system_deny_roots: list[str]) -> str | None:
    norm = path.replace("/", "\\").lower().rstrip("\\")
    for root in system_deny_roots:
        r = root.replace("/", "\\").lower().rstrip("\\")
        if r and (norm == r or norm.startswith(r + "\\")):
            return f"Path is inside a denied system root ({root})."
    return None
