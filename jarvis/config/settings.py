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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = PACKAGE_DIR / "default_config.yaml"


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
        raw = _load_yaml(cfg_path)
        defaults = _load_yaml(DEFAULT_CONFIG_PATH)
        merged = {**defaults, **raw}

        llm = merged.get("llm", {})
        limits_raw = merged.get("limits", {})
        ui = merged.get("ui", {})
        approval = merged.get("approval", {})
        network = merged.get("network", {})

        return cls(
            raw=merged,
            llm_provider=llm.get("provider", "ollama"),
            llm_host=llm.get("host", "http://127.0.0.1:11434"),
            llm_model=llm.get("model", "qwen2.5:7b-instruct"),
            llm_temperature=float(llm.get("temperature", 0.2)),
            llm_request_timeout_seconds=int(llm.get("request_timeout_seconds", 120)),
            indexed_roots=[_expand(p) for p in merged.get("indexed_roots", [])],
            excluded_dirs=list(merged.get("excluded_dirs", [])),
            system_deny_roots=[_expand(p) for p in merged.get("system_deny_roots", [])],
            limits=Limits(
                max_command_execution_seconds=int(limits_raw.get("max_command_execution_seconds", 30)),
                max_commands_per_request=int(limits_raw.get("max_commands_per_request", 5)),
                max_subprocess_count=int(limits_raw.get("max_subprocess_count", 3)),
                max_filesystem_ops_per_action=int(limits_raw.get("max_filesystem_ops_per_action", 2000)),
                max_output_bytes=int(limits_raw.get("max_output_bytes", 200_000)),
                max_recursive_depth=int(limits_raw.get("max_recursive_depth", 8)),
                max_files_scanned_per_search=int(limits_raw.get("max_files_scanned_per_search", 5000)),
            ),
            global_hotkey=ui.get("global_hotkey", "ctrl+shift+j"),
            emergency_stop_hotkey=ui.get("emergency_stop_hotkey", "ctrl+shift+esc"),
            entity_size_px=int(ui.get("entity_size_px", 96)),
            theme=ui.get("theme", "dark"),
            approval_default_scope=approval.get("default_scope", "once"),
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
