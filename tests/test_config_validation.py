"""Configuration integrity: a corrupted, malformed, or hand-edited-to-be-
dangerous config.yaml must never crash JARVIS and must never silently
weaken a security-relevant default. Every case here fails closed to a safe
value rather than trusting whatever the file said.
"""
from __future__ import annotations

import warnings
from pathlib import Path

from jarvis.config.settings import Settings


def _load_from_dict(tmp_path: Path, merged: dict) -> Settings:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return Settings._from_merged(merged, tmp_path)


def test_malformed_yaml_falls_back_to_defaults_not_a_crash(tmp_path):
    from jarvis.config import settings as settings_module

    cfg_dir = tmp_path / "data"
    cfg_dir.mkdir()
    cfg_path = cfg_dir / "config.yaml"
    cfg_path.write_text("this is: not: valid: yaml: [broken")

    original_user_data_dir = settings_module.user_data_dir
    original_user_config_path = settings_module.user_config_path
    settings_module.user_data_dir = lambda: cfg_dir
    settings_module.user_config_path = lambda: cfg_path
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            s = Settings.load()  # must not raise
        assert any("could not be parsed" in str(w.message) for w in caught)
        assert s.llm_host == "http://127.0.0.1:11434"
    finally:
        settings_module.user_data_dir = original_user_data_dir
        settings_module.user_config_path = original_user_config_path


def test_non_loopback_llm_host_is_rejected(tmp_path):
    s = _load_from_dict(tmp_path, {"llm": {"host": "http://evil.example.com:9999"}})
    assert s.llm_host == "http://127.0.0.1:11434"


def test_localhost_and_loopback_variants_are_accepted(tmp_path):
    for host in ("http://127.0.0.1:11434", "http://localhost:11434"):
        s = _load_from_dict(tmp_path, {"llm": {"host": host}})
        assert s.llm_host == host


def test_emptied_system_deny_roots_still_get_the_baseline(tmp_path):
    s = _load_from_dict(tmp_path, {"system_deny_roots": []})
    assert any("windows" in r.lower() for r in s.system_deny_roots)
    assert any("program files" in r.lower() for r in s.system_deny_roots)


def test_config_cannot_remove_baseline_deny_roots_even_by_overlap(tmp_path):
    # Config CAN add more deny roots; it cannot end up with fewer than the
    # hardcoded baseline no matter what it lists.
    s = _load_from_dict(tmp_path, {"system_deny_roots": ["D:\\SomethingElse"]})
    lowered = [r.lower() for r in s.system_deny_roots]
    assert any("windows" in r for r in lowered)
    assert any("somethingelse" in r for r in lowered)


def test_whole_drive_as_indexed_root_is_refused(tmp_path):
    s = _load_from_dict(tmp_path, {"indexed_roots": ["C:\\", "C:", "/"]})
    assert s.indexed_roots == []


def test_out_of_range_limits_are_clamped_not_trusted(tmp_path):
    s = _load_from_dict(tmp_path, {"limits": {
        "max_subprocess_count": 999999,
        "max_command_execution_seconds": -5,
    }})
    assert s.limits.max_subprocess_count == 50   # clamped to the upper bound
    assert s.limits.max_command_execution_seconds == 1  # clamped to the lower bound


def test_non_integer_limit_falls_back_to_default(tmp_path):
    s = _load_from_dict(tmp_path, {"limits": {"max_subprocess_count": "unlimited"}})
    assert s.limits.max_subprocess_count == 3  # the packaged default


def test_unrecognized_approval_scope_falls_back_to_safest(tmp_path):
    s = _load_from_dict(tmp_path, {"approval": {"default_scope": "always_allow_everything"}})
    assert s.approval_default_scope == "once"


def test_non_dict_top_level_sections_do_not_crash(tmp_path):
    # e.g. a config.yaml where someone wrote "limits: yes" instead of a mapping
    s = _load_from_dict(tmp_path, {"limits": "yes", "llm": "no", "ui": 5})
    assert s.limits.max_subprocess_count == 3
    assert s.llm_host == "http://127.0.0.1:11434"
