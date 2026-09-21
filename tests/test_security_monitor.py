"""SecurityMonitor watches the STREAM of policy decisions, not individual
requests. A single denial is normal; a pattern of repeated denials or
repeated attempts at the same blocked tool is a signal worth escalating on,
independent of anything the LLM said or claimed.
"""
from __future__ import annotations

from jarvis.security.monitor import SecurityMonitor
from jarvis.security.permissions import ActionRequest, Decision, PermissionLevel, PolicyDecision, RiskLevel


def _deny_decision(reasons=None) -> PolicyDecision:
    return PolicyDecision(Decision.DENY, PermissionLevel.DENY, RiskLevel.CRITICAL, reasons or ["denied"])


def _confirm_decision() -> PolicyDecision:
    return PolicyDecision(Decision.CONFIRM, PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH, ["needs approval"])


def test_single_denial_does_not_trigger_an_alert():
    monitor = SecurityMonitor(denial_threshold=3, blocked_tool_threshold=3)
    request = ActionRequest(tool_name="disable_windows_defender", args={})
    alert = monitor.observe(request, _deny_decision())
    assert alert is None
    assert monitor.active_lockouts() == {}


def test_repeated_denials_of_the_same_tool_triggers_lockout():
    monitor = SecurityMonitor(denial_threshold=10, blocked_tool_threshold=3, lockout_seconds=60)
    request = ActionRequest(tool_name="execute_command", command="rm -rf /", cwd="/tmp")
    alert = None
    for _ in range(3):
        alert = monitor.observe(request, _deny_decision())
    assert alert is not None
    assert alert.kind == "repeated_blocked_tool_attempts"
    assert "execute_command" in monitor.active_lockouts()


def test_lockout_causes_check_lockout_to_refuse_further_attempts():
    monitor = SecurityMonitor(blocked_tool_threshold=2, lockout_seconds=60)
    request = ActionRequest(tool_name="execute_command", command="rm -rf /", cwd="/tmp")
    monitor.observe(request, _deny_decision())
    monitor.observe(request, _deny_decision())

    reason = monitor.check_lockout(ActionRequest(tool_name="execute_command", command="git status", cwd="/tmp"))
    assert reason is not None
    assert "locked out" in reason.lower()


def test_lockout_does_not_affect_other_tools():
    monitor = SecurityMonitor(blocked_tool_threshold=2, lockout_seconds=60)
    request = ActionRequest(tool_name="execute_command", command="rm -rf /", cwd="/tmp")
    monitor.observe(request, _deny_decision())
    monitor.observe(request, _deny_decision())

    reason = monitor.check_lockout(ActionRequest(tool_name="get_memory_usage", args={}))
    assert reason is None


def test_manual_clear_lockout_removes_it():
    monitor = SecurityMonitor(blocked_tool_threshold=2, lockout_seconds=60)
    request = ActionRequest(tool_name="execute_command", command="rm -rf /", cwd="/tmp")
    monitor.observe(request, _deny_decision())
    monitor.observe(request, _deny_decision())
    assert "execute_command" in monitor.active_lockouts()

    cleared = monitor.clear_lockout("execute_command")
    assert cleared == 1
    assert monitor.active_lockouts() == {}
    assert monitor.check_lockout(request) is None


def test_repeated_denials_across_different_tools_triggers_general_alert():
    monitor = SecurityMonitor(denial_threshold=3, blocked_tool_threshold=100)
    tools = ["read_ssh_private_key", "disable_windows_defender", "grant_admin_privileges"]
    alert = None
    for name in tools:
        alert = monitor.observe(ActionRequest(tool_name=name, args={}), _deny_decision())
    assert alert is not None
    assert alert.kind == "repeated_denials"


def test_rapid_gated_action_chaining_triggers_alert():
    monitor = SecurityMonitor(rapid_action_threshold=4, rapid_action_window_seconds=10)
    alert = None
    for i in range(4):
        alert = monitor.observe(ActionRequest(tool_name="execute_command", command=f"pip install pkg{i}", cwd="/tmp"), _confirm_decision())
    assert alert is not None
    assert alert.kind == "rapid_action_chaining"


def test_allowed_actions_never_trigger_alerts():
    monitor = SecurityMonitor(denial_threshold=1, blocked_tool_threshold=1, rapid_action_threshold=1)
    allow = PolicyDecision(Decision.ALLOW, PermissionLevel.READ, RiskLevel.LOW, [])
    for _ in range(20):
        alert = monitor.observe(ActionRequest(tool_name="get_memory_usage", args={}), allow)
        assert alert is None


def test_alert_is_recorded_to_audit_sink():
    events = []

    class FakeAudit:
        def record(self, **kwargs):
            events.append(kwargs)

    monitor = SecurityMonitor(audit_sink=FakeAudit(), blocked_tool_threshold=2, lockout_seconds=60)
    request = ActionRequest(tool_name="execute_command", command="rm -rf /", cwd="/tmp")
    monitor.observe(request, _deny_decision())
    monitor.observe(request, _deny_decision())

    assert any(e.get("event_type") == "security_alert" for e in events)


def test_recent_alerts_returns_history():
    monitor = SecurityMonitor(blocked_tool_threshold=2, lockout_seconds=60)
    request = ActionRequest(tool_name="execute_command", command="rm -rf /", cwd="/tmp")
    monitor.observe(request, _deny_decision())
    monitor.observe(request, _deny_decision())
    alerts = monitor.recent_alerts()
    assert len(alerts) == 1
    assert alerts[0].kind == "repeated_blocked_tool_attempts"
