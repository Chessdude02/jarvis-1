"""The Security Center is a plain UI surface over real backend calls -- these
tests construct it under Qt's offscreen platform and exercise every control,
confirming each one actually calls through to KillSwitch/Memory/AuditLog
rather than just updating its own display state.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


class _FakeCtx:
    """A minimal stand-in for JarvisApp exposing only what SecurityCenterWindow reads."""

    def __init__(self, settings, registry, memory, sandbox, kill_switch, security_monitor, audit_log, llm_client,
                 lockdown_manager=None, rate_limiter=None):
        self.settings = settings
        self.registry = registry
        self.memory = memory
        self.sandbox = sandbox
        self.kill_switch = kill_switch
        self.security_monitor = security_monitor
        self.audit_log = audit_log
        self.llm_client = llm_client
        self.lockdown_manager = lockdown_manager
        self.rate_limiter = rate_limiter


class _FakeLLM:
    def is_available(self):
        return False


def _make_ctx(settings, registry, memory, sandbox, audit_log):
    from jarvis.security.kill_switch import KillSwitch
    from jarvis.security.lockdown import LockdownManager
    from jarvis.security.monitor import SecurityMonitor
    from jarvis.security.rate_limiter import RateLimiter

    lockdown = LockdownManager(audit_sink=audit_log)
    monitor = SecurityMonitor(audit_sink=audit_log, lockdown_manager=lockdown)
    ks = KillSwitch(sandbox, audit_sink=audit_log, security_monitor=monitor)
    rate_limiter = RateLimiter(audit_sink=audit_log)
    return _FakeCtx(settings, registry, memory, sandbox, ks, monitor, audit_log, _FakeLLM(),
                     lockdown_manager=lockdown, rate_limiter=rate_limiter)


def test_security_center_constructs_and_refreshes(qapp, settings, registry, memory, sandbox, audit_log):
    from jarvis.ui.security_center import SecurityCenterWindow

    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    window = SecurityCenterWindow(ctx)
    assert "Tools enabled" in window.status_label.text()
    window.close()


def test_revoke_session_permissions_control_calls_memory(qapp, settings, registry, memory, sandbox, audit_log):
    from jarvis.ui.security_center import SecurityCenterWindow

    memory.add_session_grant("execute_command:pip:proj")
    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    window = SecurityCenterWindow(ctx)
    assert memory.has_grant("execute_command:pip:proj")

    window._revoke_session_permissions()
    assert not memory.has_grant("execute_command:pip:proj")
    window.close()


def test_reset_all_permissions_clears_persisted_grants_too(qapp, settings, registry, memory, sandbox, audit_log):
    from jarvis.ui.security_center import SecurityCenterWindow

    memory.add_permanent_grant("execute_command:pip:proj")
    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    window = SecurityCenterWindow(ctx)

    window._reset_all_permissions()
    assert not memory.has_grant("execute_command:pip:proj")
    window.close()


def test_toggle_terminal_control_flips_kill_switch(qapp, settings, registry, memory, sandbox, audit_log):
    from jarvis.ui.security_center import SecurityCenterWindow

    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    window = SecurityCenterWindow(ctx)
    assert ctx.kill_switch.is_terminal_disabled() is False

    window._toggle_terminal()
    assert ctx.kill_switch.is_terminal_disabled() is True
    assert "Enable Terminal" in window.btn_toggle_terminal.text()

    window._toggle_terminal()
    assert ctx.kill_switch.is_terminal_disabled() is False
    window.close()


def test_toggle_network_control_flips_kill_switch(qapp, settings, registry, memory, sandbox, audit_log):
    from jarvis.ui.security_center import SecurityCenterWindow

    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    window = SecurityCenterWindow(ctx)
    window._toggle_network()
    assert ctx.kill_switch.is_network_disabled() is True
    window.close()


def test_clear_lockouts_control_calls_monitor(qapp, settings, registry, memory, sandbox, audit_log):
    from jarvis.security.permissions import ActionRequest, Decision, PermissionLevel, PolicyDecision, RiskLevel
    from jarvis.ui.security_center import SecurityCenterWindow

    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    deny = PolicyDecision(Decision.DENY, PermissionLevel.DENY, RiskLevel.CRITICAL, ["x"])
    req = ActionRequest(tool_name="execute_command", command="bad", cwd="/tmp")
    ctx.security_monitor.blocked_tool_threshold = 2
    ctx.security_monitor.observe(req, deny)
    ctx.security_monitor.observe(req, deny)
    assert ctx.security_monitor.active_lockouts()

    window = SecurityCenterWindow(ctx)
    window._clear_lockouts()
    assert not ctx.security_monitor.active_lockouts()
    window.close()


def test_view_audit_log_opens_viewer_with_verified_chain(qapp, settings, registry, memory, sandbox, audit_log):
    from jarvis.ui.security_center import SecurityCenterWindow

    audit_log.record("test_event", note="hello")
    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    window = SecurityCenterWindow(ctx)
    window._view_audit_log()
    assert window.audit_view is not None
    assert "VERIFIED" in window.audit_view.verify_label.text()
    assert "test_event" in window.audit_view.text.toPlainText()
    window.audit_view.close()
    window.close()


def test_reset_rate_limits_control_calls_rate_limiter(qapp, settings, registry, memory, sandbox, audit_log):
    from jarvis.ui.security_center import SecurityCenterWindow

    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    ctx.rate_limiter.check_and_record("user_message")
    assert ctx.rate_limiter.status()["user_message"]["recent_events"] == 1

    window = SecurityCenterWindow(ctx)
    window._reset_rate_limits()
    assert ctx.rate_limiter.status()["user_message"]["recent_events"] == 0
    window.close()


def test_toggle_lockdown_enters_and_exits_with_confirmation(qapp, settings, registry, memory, sandbox, audit_log):
    from unittest.mock import patch
    from PySide6.QtWidgets import QMessageBox
    from jarvis.ui.security_center import SecurityCenterWindow

    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    window = SecurityCenterWindow(ctx)
    assert not ctx.lockdown_manager.is_locked_down()
    assert window.btn_toggle_lockdown.text() == "Enter Lockdown"

    with patch.object(QMessageBox, "question", return_value=QMessageBox.Yes):
        window._toggle_lockdown()
    assert ctx.lockdown_manager.is_locked_down()
    assert window.btn_toggle_lockdown.text() == "Exit Lockdown"

    with patch.object(QMessageBox, "question", return_value=QMessageBox.Yes):
        window._toggle_lockdown()
    assert not ctx.lockdown_manager.is_locked_down()
    window.close()


def test_toggle_lockdown_declining_confirmation_does_nothing(qapp, settings, registry, memory, sandbox, audit_log):
    from unittest.mock import patch
    from PySide6.QtWidgets import QMessageBox
    from jarvis.ui.security_center import SecurityCenterWindow

    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    window = SecurityCenterWindow(ctx)

    with patch.object(QMessageBox, "question", return_value=QMessageBox.No):
        window._toggle_lockdown()
    assert not ctx.lockdown_manager.is_locked_down()
    window.close()


def test_lockdown_status_reflected_in_refresh(qapp, settings, registry, memory, sandbox, audit_log):
    from jarvis.ui.security_center import SecurityCenterWindow

    ctx = _make_ctx(settings, registry, memory, sandbox, audit_log)
    window = SecurityCenterWindow(ctx)
    assert "NORMAL" in window.lockdown_label.text()

    ctx.lockdown_manager.enter_lockdown("test trigger")
    window.refresh()
    assert "LOCKDOWN" in window.lockdown_label.text()
    assert "test trigger" in window.lockdown_label.text()
    window.close()
