"""The kill-switch hierarchy must work as plain method calls, independent of
the orchestrator/LLM -- these tests call KillSwitch directly, the same way
a hotkey handler or Security Center button would, with no LLM involved.
"""
from __future__ import annotations

import sys
import threading
import time

import pytest

from jarvis.security.kill_switch import KillSwitch


def test_cancel_current_action_with_nothing_running_returns_false(sandbox):
    ks = KillSwitch(sandbox)
    assert ks.cancel_current_action() is False


@pytest.mark.skipif(sys.platform == "win32", reason="uses posix shell built-ins")
def test_cancel_current_action_kills_only_the_most_recent(settings, tmp_path):
    from jarvis.security.sandbox import Sandbox

    settings.limits.max_command_execution_seconds = 10
    settings.limits.max_subprocess_count = 5
    sb = Sandbox(settings)
    ks = KillSwitch(sb)

    results = {}

    def run(name, delay=0):
        if delay:
            time.sleep(delay)
        results[name] = sb.run("sleep 5", str(tmp_path))

    t1 = threading.Thread(target=run, args=("first",))
    t1.start()
    time.sleep(0.3)
    t2 = threading.Thread(target=run, args=("second",))
    t2.start()
    time.sleep(0.3)

    assert sb.active_count == 2
    cancelled = ks.cancel_current_action()  # should cancel "second" only
    assert cancelled is True
    time.sleep(0.3)
    assert sb.active_count == 1  # "first" still running

    ks.stop_all_actions()  # cleanup
    t1.join(timeout=10)
    t2.join(timeout=10)


def test_stop_all_actions_calls_registered_orchestrator_callback(sandbox):
    ks = KillSwitch(sandbox)
    called = []
    ks.register_orchestrator_stop(lambda: called.append(True))
    ks.stop_all_actions()
    assert called == [True]


def test_disable_terminal_toggles_state():
    ks = KillSwitch(sandbox=None)
    assert ks.is_terminal_disabled() is False
    ks.disable_terminal()
    assert ks.is_terminal_disabled() is True
    ks.enable_terminal()
    assert ks.is_terminal_disabled() is False


def test_disable_network_toggles_state():
    ks = KillSwitch(sandbox=None)
    assert ks.is_network_disabled() is False
    ks.disable_network()
    assert ks.is_network_disabled() is True
    ks.enable_network()
    assert ks.is_network_disabled() is False


def test_request_exit_does_not_raise_without_audit_sink():
    ks = KillSwitch(sandbox=None)
    ks.request_exit()  # must not raise


def test_status_reports_full_state(sandbox):
    ks = KillSwitch(sandbox)
    ks.disable_terminal()
    ks.disable_network()
    status = ks.status()
    assert status["terminal_disabled"] is True
    assert status["network_disabled"] is True
    assert status["active_processes"] == 0


def test_every_level_is_audited():
    events = []

    class FakeAudit:
        def record(self, **kwargs):
            events.append(kwargs["event_type"])

    ks = KillSwitch(sandbox=None, audit_sink=FakeAudit())
    ks.cancel_current_action()
    ks.stop_all_actions()
    ks.disable_terminal()
    ks.disable_network()
    ks.request_exit()

    for expected in ("kill_switch_level1_cancel_current", "kill_switch_level2_stop_all",
                      "kill_switch_level3_disable_terminal", "kill_switch_level4_disable_network",
                      "kill_switch_level5_exit_requested"):
        assert expected in events, f"missing audit event: {expected}"


def test_policy_engine_denies_execute_command_when_terminal_disabled(settings, registry, audit_log):
    from jarvis.security.kill_switch import KillSwitch
    from jarvis.security.permissions import ActionRequest, Decision
    from jarvis.security.policy_engine import PolicyEngine

    ks = KillSwitch(sandbox=None, audit_sink=audit_log)
    ks.disable_terminal()
    engine = PolicyEngine(settings, registry.policy_specs(), audit_sink=audit_log, kill_switch=ks)

    project = settings.indexed_roots[0]
    # Even a completely harmless read-only command is refused while disabled.
    decision = engine.evaluate(ActionRequest(tool_name="execute_command", command="git status", cwd=project, paths=[project]))
    assert decision.decision == Decision.DENY
    assert "disabled" in " ".join(decision.reasons).lower()

    ks.enable_terminal()
    decision2 = engine.evaluate(ActionRequest(tool_name="execute_command", command="git status", cwd=project, paths=[project]))
    assert decision2.decision == Decision.ALLOW


def test_terminal_disable_does_not_affect_other_tools(settings, registry, audit_log):
    from jarvis.security.kill_switch import KillSwitch
    from jarvis.security.permissions import ActionRequest, Decision
    from jarvis.security.policy_engine import PolicyEngine

    ks = KillSwitch(sandbox=None, audit_sink=audit_log)
    ks.disable_terminal()
    engine = PolicyEngine(settings, registry.policy_specs(), audit_sink=audit_log, kill_switch=ks)

    decision = engine.evaluate(ActionRequest(tool_name="get_memory_usage", args={}))
    assert decision.decision == Decision.ALLOW
