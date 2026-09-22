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
    "/etc/shadow", "/etc/gshadow",  # Linux password/group hashes
    "/library/keychains/", "login.keychain",  # macOS Keychain
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

# --- "JARVIS must not become an attack tool" (network/credential/exploit
# tooling). These are outright denied, not merely gated as DESTRUCTIVE --
# per the spec, a network scanner, credential cracker, or exploit runner
# "must not exist in the normal JARVIS toolset" at all, which is a
# stronger bar than "requires approval". Anchored to the actual binary
# names/argument styles of real tools, not generic words, to avoid
# false-positiving on unrelated commands (e.g. "john" alone is a common
# name, so it's paired with John the Ripper's own flag style below).
#
# Kept in a separate tuple from DENY_COMMAND_PATTERNS and matched against
# an aggressively deobfuscated form of the command (see
# _deobfuscate_for_attack_tool_matching below) -- unlike the
# security-control patterns above, none of these need a literal backslash
# or quote character to match, so it's safe to strip those wholesale here
# to close the classic shell defense-evasion trick of inserting an escaped
# character or an empty quote pair mid-word ("n\map", "n''map", "hy\dra")
# to break up a \bword\b regex without changing what a real shell executes
# (verified: bash parses both n\map and n''map as the literal command
# "nmap"). Found by testing this exact evasion against the patterns below.
ATTACK_TOOL_PATTERNS: tuple[re.Pattern, ...] = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\bnmap\b",
    r"\bmasscan\b",
    r"\bzmap\b",
    r"\bhydra\b",
    r"\bmedusa\s+-[a-z]*h\b",  # medusa brute-forcer (its -h differs from --help usage)
    r"\bsqlmap\b",
    r"\bmsfconsole\b|\bmsfvenom\b|\bmsfdb\b",
    r"\bmetasploit\b",
    r"\bhashcat\b",
    r"\bjohn\b.*(--wordlist|--format=)",  # John the Ripper, not the name "john"
    r"\baircrack-ng\b|\bairodump-ng\b|\baireplay-ng\b",
    r"\bresponder\.py\b|\bResponder\b.*-i\b",
    r"\bmimikatz\b",
    r"\bcrackmapexec\b|\bcme\s+(smb|winrm|ssh|mssql)\b",
    r"\bevil-winrm\b",
    r"\bbettercap\b|\bettercap\b",
    r"\bwpscan\b",
    r"\bnikto\b",
    r"\bsharphound\b|\bbloodhound\.py\b",
    r"\blazagne\b",
    r"\bbeef-xss\b",
    r"\b(nc|ncat|netcat)\b[^|;&\n]*(-e|--exec|--sh-exec)\s+\S",  # reverse/bind shell via execute flag
    r"\bsetoolkit\b",  # Social-Engineer Toolkit
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


# Every quote character and backslash, stripped wholesale. Only used for
# matching ATTACK_TOOL_PATTERNS (see comment above that tuple) -- unlike
# normalize_command(), this is deliberately NOT applied ahead of the other
# DENY_COMMAND_PATTERNS or command_validator's destructive-pattern list,
# several of which rely on a literal backslash to match a Windows path
# fragment (e.g. "\\policies\\"); stripping backslashes there would
# regress those checks instead of strengthening them.
_QUOTE_AND_BACKSLASH = re.compile(r"['\"\\]")

# The classic homoglyph set used to typosquat/spoof ASCII text: Cyrillic,
# Greek, and Armenian letters that render visually identical (or near-
# identical) to a Latin letter in most fonts, mapped to that Latin letter.
# Found by testing: "nmар -sV target" (Cyrillic а U+0430 and р U+0440,
# everything else ASCII) evaded \bnmap\b entirely -- the string just isn't
# "nmap" at the codepoint level -- degrading the deny to a plain
# "unknown command shape" DESTRUCTIVE, same as the quote/backslash gap.
# Deliberately a small, curated table of the letters actually used in
# real-world confusable attacks, not a full Unicode confusables database.
_HOMOGLYPH_TO_LATIN = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",  # Cyrillic
    "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ո": "n", "ѡ": "w",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y",
    "Ι": "I", "Κ": "K", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",  # Greek
})


def _deobfuscate_for_attack_tool_matching(command: str) -> str:
    command = command.translate(_HOMOGLYPH_TO_LATIN)
    return _QUOTE_AND_BACKSLASH.sub("", command)


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
    deobfuscated = _deobfuscate_for_attack_tool_matching(normalized)
    for pattern in ATTACK_TOOL_PATTERNS:
        if pattern.search(deobfuscated):
            return f"Command matches a denied attack-tool pattern ({pattern.pattern})."
    # Found by testing: execute_command's build_request() only ever puts
    # `cwd` into request.paths -- a credential path referenced as an
    # ARGUMENT inside the command string itself ("cat ~/.ssh/id_rsa", "type
    # C:\Users\bob\.ssh\id_rsa", "get-content ...\Cookies") was never run
    # through denied_path() at all, and cat/type/get-content all classify
    # as a READ prefix -- confirmed via the real PolicyEngine: all of the
    # above evaluated to ALLOW with zero confirmation, fully bypassing
    # DENY_PATH_FRAGMENTS despite it being built specifically to stop this.
    # denied_path()'s substring check works the same whether it's handed an
    # isolated path or a whole command line, so reusing it here (rather
    # than trying to parse out every possible path-argument position across
    # every shell/tool's argument syntax) closes the bypass uniformly for
    # cat/type/get-content/less/head/tail/python -c "open(...)"/etc. at
    # once, independent of is_command_tool or category resolution (this
    # function is also called directly from step 1e of
    # PolicyEngine._evaluate, unconditionally).
    path_reason = denied_path(normalized)
    if path_reason:
        return f"Command references a credential/security-sensitive location: {path_reason}"
    return None


def denied_system_root(path: str, system_deny_roots: list[str]) -> str | None:
    norm = path.replace("/", "\\").lower().rstrip("\\")
    for root in system_deny_roots:
        r = root.replace("/", "\\").lower().rstrip("\\")
        if r and (norm == r or norm.startswith(r + "\\")):
            return f"Path is inside a denied system root ({root})."
    return None
