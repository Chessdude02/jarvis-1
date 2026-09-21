from __future__ import annotations

import pytest

from jarvis.config.settings import Limits, Settings
from jarvis.core.memory import Memory
from jarvis.security.audit import AuditLog
from jarvis.security.policy_engine import PolicyEngine
from jarvis.security.sandbox import Sandbox
from jarvis.tools.registry import build_default_registry


@pytest.fixture
def settings(tmp_path):
    project_root = tmp_path / "Projects"
    project_root.mkdir()
    return Settings(
        indexed_roots=[str(project_root)],
        excluded_dirs=[".git", "node_modules", "__pycache__", ".venv"],
        system_deny_roots=["C:\\Windows", "C:\\Program Files"],
        limits=Limits(
            max_command_execution_seconds=3,
            max_commands_per_request=5,
            max_subprocess_count=2,
            max_filesystem_ops_per_action=1000,
            max_output_bytes=2000,
            max_recursive_depth=5,
            max_files_scanned_per_search=1000,
        ),
        data_dir=tmp_path,
    )


@pytest.fixture
def registry():
    return build_default_registry()


@pytest.fixture
def audit_log(tmp_path):
    log = AuditLog(tmp_path / "audit.db")
    yield log
    log.close()


@pytest.fixture
def memory(tmp_path):
    m = Memory(tmp_path / "memory.db")
    yield m
    m.close()


@pytest.fixture
def policy_engine(settings, registry, audit_log, memory):
    # Matches production wiring (jarvis/ui/app.py): grant_store=memory, so
    # SESSION/ALWAYS approvals actually persist the way the real app relies
    # on. Tests that need a different/fake grant store override
    # policy_engine.grant_store directly.
    return PolicyEngine(settings, registry.policy_specs(), grant_store=memory, audit_sink=audit_log)


@pytest.fixture
def sandbox(settings):
    return Sandbox(settings)
