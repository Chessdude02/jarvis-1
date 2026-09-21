"""Loads and resolves JARVIS configuration.

Precedence: user config file (created on first run from default_config.yaml)
overlaid with any values in it. There is no environment-variable or CLI
override for security-relevant fields (limits, deny roots) -- those are only
editable by hand-editing the user config file, which keeps the LLM from ever
influencing its own guardrails at runtime.
"""
from __future__ import annotations

import os
import shutil
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = PACKAGE_DIR / "default_config.yaml"

# A config edit (accidental or otherwise) can only ADD to this baseline, never
# remove it -- these are unioned into system_deny_roots after loading,
# regardless of what the user config says. Without this, emptying
# system_deny_roots in config.yaml would silently remove the one guard that
# keeps JARVIS out of C:\Windows and Program Files.
_MINIMUM_SYSTEM_DENY_ROOTS = (
    "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\ProgramData",
)

# Loopback-only, by construction, not just by docstring claim: core JARVIS
# functionality is supposed to never make a network call anywhere but a
# local Ollama server. If llm.host in config.yaml is ever edited to point
# somewhere else (by a person, or by a corrupted/tampered file), loading
# must refuse that value rather than silently start sending prompts to an
# arbitrary remote host.
_ALLOWED_LLM_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1", "0.0.0.0"})

_ALLOWED_APPROVAL_SCOPES = frozenset({"once", "session", "always_this_action"})

# (field, minimum, maximum, fallback) -- out-of-range or non-numeric values
# are clamped/replaced rather than trusted, so a corrupted or hand-edited
# config can't quietly disable resource limiting by setting e.g.
# max_subprocess_count to 999999.
_LIMIT_BOUNDS: dict[str, tuple[int, int, int]] = {
    "max_command_execution_seconds": (1, 3600, 30),
    "max_commands_per_request": (1, 100, 5),
    "max_subprocess_count": (1, 50, 3),
    "max_filesystem_ops_per_action": (1, 200_000, 2000),
    "max_output_bytes": (1024, 50_000_000, 200_000),
    "max_recursive_depth": (1, 100, 8),
    "max_files_scanned_per_search": (1, 500_000, 5000),
}


def _warn(message: str) -> None:
    warnings.warn(f"JARVIS config: {message}", stacklevel=3)


def _clamped_int(raw: Any, bounds: tuple[int, int, int], field_name: str) -> int:
    lo, hi, fallback = bounds
    try:
        value = int(raw)
    except (TypeError, ValueError):
        _warn(f"limits.{field_name} is not a valid integer ({raw!r}); using default {fallback}.")
        return fallback
    if value < lo or value > hi:
        clamped = max(lo, min(hi, value))
        _warn(f"limits.{field_name}={value} is outside the allowed range [{lo}, {hi}]; clamped to {clamped}.")
        return clamped
    return value


def _validate_llm_host(host: Any, fallback: str) -> str:
    if not isinstance(host, str):
        _warn(f"llm.host is not a string ({host!r}); using default {fallback}.")
        return fallback
    try:
        hostname = urlparse(host).hostname
    except ValueError:
        hostname = None
    if hostname not in _ALLOWED_LLM_HOSTNAMES:
        _warn(f"llm.host={host!r} is not a loopback address; refusing it and using default {fallback}. "
              f"JARVIS only ever talks to a local Ollama server.")
        return fallback
    return host


def _validate_string_list(raw: Any, field_name: str) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(p, str) for p in raw):
        _warn(f"{field_name} is not a list of strings; ignoring it and using no entries.")
        return []
    return raw


def _validate_indexed_roots(roots: list[str]) -> list[str]:
    """Refuses an entry that IS a drive root / filesystem root outright --
    that would mean 'index the whole drive', which is explicitly disallowed
    regardless of what the config says.
    """
    safe = []
    for root in roots:
        expanded = _expand(root)
        normalized = expanded.replace("/", "\\").rstrip("\\")
        is_drive_root = len(normalized) <= 3 and normalized.endswith(":") or normalized in ("", "\\") or expanded in ("/", "")
        if is_drive_root:
            _warn(f"indexed_roots entry {root!r} resolves to a filesystem root; refusing to index an entire drive.")
            continue
        safe.append(expanded)
    return safe


def _validate_approval_scope(raw: Any, fallback: str = "once") -> str:
    if raw not in _ALLOWED_APPROVAL_SCOPES:
        _warn(f"approval.default_scope={raw!r} is not a recognized scope; using the safest default {fallback!r}.")
        return fallback
    return raw


def user_data_dir() -> Path:
    """Per-user, per-machine directory for config, memory DB, audit DB, logs."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "JARVIS"
    return Path.home() / ".jarvis"


def user_config_path() -> Path:
    return user_data_dir() / "config.yaml"


def _expand(value: str) -> str:
    return os.path.expandvars(os.path.expanduser(value))


def _load_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@dataclass
class Limits:
    max_command_execution_seconds: int = 30
    max_commands_per_request: int = 5
    max_subprocess_count: int = 3
    max_filesystem_ops_per_action: int = 2000
    max_output_bytes: int = 200_000
    max_recursive_depth: int = 8
    max_files_scanned_per_search: int = 5000


@dataclass
class Settings:
    raw: dict = field(default_factory=dict)

    llm_provider: str = "ollama"
    llm_host: str = "http://127.0.0.1:11434"
    llm_model: str = "qwen2.5:7b-instruct"
    llm_temperature: float = 0.2
    llm_request_timeout_seconds: int = 120

    indexed_roots: list[str] = field(default_factory=list)
    excluded_dirs: list[str] = field(default_factory=list)
    system_deny_roots: list[str] = field(default_factory=list)

    limits: Limits = field(default_factory=Limits)

    global_hotkey: str = "ctrl+shift+j"
    emergency_stop_hotkey: str = "ctrl+shift+esc"
    entity_size_px: int = 96
    theme: str = "dark"

    approval_default_scope: str = "once"
    online_features_enabled: bool = False

    data_dir: Path = field(default_factory=user_data_dir)

    @classmethod
    def load(cls) -> "Settings":
        data_dir = user_data_dir()
        data_dir.mkdir(parents=True, exist_ok=True)
        cfg_path = user_config_path()
        if not cfg_path.exists():
            shutil.copyfile(DEFAULT_CONFIG_PATH, cfg_path)

        defaults = _load_yaml(DEFAULT_CONFIG_PATH)
        try:
            raw = _load_yaml(cfg_path)
        except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
            # Fail closed: a corrupt or unreadable user config must not
            # crash JARVIS or run with a half-applied/undefined merge --
            # it falls back to the packaged defaults only, same as if the
            # file didn't exist.
            _warn(f"{cfg_path} could not be parsed ({exc}); falling back to packaged defaults only.")
            raw = {}
        if not isinstance(raw, dict):
            _warn(f"{cfg_path} does not contain a YAML mapping at the top level; falling back to packaged defaults only.")
            raw = {}

        merged = {**defaults, **raw}
        return cls._from_merged(merged, data_dir)

    @classmethod
    def _from_merged(cls, merged: dict, data_dir: Path) -> "Settings":
        llm = merged.get("llm") if isinstance(merged.get("llm"), dict) else {}
        limits_raw = merged.get("limits") if isinstance(merged.get("limits"), dict) else {}
        ui = merged.get("ui") if isinstance(merged.get("ui"), dict) else {}
        approval = merged.get("approval") if isinstance(merged.get("approval"), dict) else {}
        network = merged.get("network") if isinstance(merged.get("network"), dict) else {}

        indexed_roots = _validate_indexed_roots(_validate_string_list(merged.get("indexed_roots", []), "indexed_roots"))
        system_deny_roots = [_expand(p) for p in _validate_string_list(merged.get("system_deny_roots", []), "system_deny_roots")]
        # Union, never replace: the baseline can only be strengthened by
        # config, never weakened by an edited/corrupted/empty list.
        for baseline in _MINIMUM_SYSTEM_DENY_ROOTS:
            if not any(os.path.normcase(baseline) == os.path.normcase(existing) for existing in system_deny_roots):
                system_deny_roots.append(baseline)

        return cls(
            raw=merged,
            llm_provider=llm.get("provider", "ollama"),
            llm_host=_validate_llm_host(llm.get("host", "http://127.0.0.1:11434"), "http://127.0.0.1:11434"),
            llm_model=llm.get("model", "qwen2.5:7b-instruct") if isinstance(llm.get("model"), str) else "qwen2.5:7b-instruct",
            llm_temperature=float(llm.get("temperature", 0.2)) if isinstance(llm.get("temperature", 0.2), (int, float)) else 0.2,
            llm_request_timeout_seconds=_clamped_int(llm.get("request_timeout_seconds", 120), (5, 600, 120), "llm_request_timeout_seconds"),
            indexed_roots=indexed_roots,
            excluded_dirs=_validate_string_list(merged.get("excluded_dirs", []), "excluded_dirs"),
            system_deny_roots=system_deny_roots,
            limits=Limits(
                max_command_execution_seconds=_clamped_int(limits_raw.get("max_command_execution_seconds"), _LIMIT_BOUNDS["max_command_execution_seconds"], "max_command_execution_seconds"),
                max_commands_per_request=_clamped_int(limits_raw.get("max_commands_per_request"), _LIMIT_BOUNDS["max_commands_per_request"], "max_commands_per_request"),
                max_subprocess_count=_clamped_int(limits_raw.get("max_subprocess_count"), _LIMIT_BOUNDS["max_subprocess_count"], "max_subprocess_count"),
                max_filesystem_ops_per_action=_clamped_int(limits_raw.get("max_filesystem_ops_per_action"), _LIMIT_BOUNDS["max_filesystem_ops_per_action"], "max_filesystem_ops_per_action"),
                max_output_bytes=_clamped_int(limits_raw.get("max_output_bytes"), _LIMIT_BOUNDS["max_output_bytes"], "max_output_bytes"),
                max_recursive_depth=_clamped_int(limits_raw.get("max_recursive_depth"), _LIMIT_BOUNDS["max_recursive_depth"], "max_recursive_depth"),
                max_files_scanned_per_search=_clamped_int(limits_raw.get("max_files_scanned_per_search"), _LIMIT_BOUNDS["max_files_scanned_per_search"], "max_files_scanned_per_search"),
            ),
            global_hotkey=ui.get("global_hotkey", "ctrl+shift+j") if isinstance(ui.get("global_hotkey"), str) else "ctrl+shift+j",
            emergency_stop_hotkey=ui.get("emergency_stop_hotkey", "ctrl+shift+esc") if isinstance(ui.get("emergency_stop_hotkey"), str) else "ctrl+shift+esc",
            entity_size_px=_clamped_int(ui.get("entity_size_px", 96), (32, 512, 96), "entity_size_px"),
            theme=ui.get("theme", "dark") if ui.get("theme") in ("dark", "light") else "dark",
            approval_default_scope=_validate_approval_scope(approval.get("default_scope", "once")),
            online_features_enabled=bool(network.get("online_features_enabled", False)),
            data_dir=data_dir,
        )

    @property
    def memory_db_path(self) -> Path:
        return self.data_dir / "memory.db"

    @property
    def audit_db_path(self) -> Path:
        return self.data_dir / "audit.db"


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.load()
    return _settings
