"""Compromised-JARVIS mode: NORMAL -> SUSPICIOUS -> LOCKDOWN. This is a
single global gate, more absolute than a per-tool SecurityMonitor lockout
-- LOCKDOWN blocks nearly everything, and the only way out is an explicit
human confirmation, never anything the LLM says or does.
"""
from __future__ import annotations

from jarvis.security.lockdown import LOCKDOWN_ALLOWED_TOOLS, LockdownManager, SecurityState


def test_starts_normal():
    ld = LockdownManager()
    assert ld.state == SecurityState.NORMAL
    assert not ld.is_locked_down()
    assert ld.is_normal()


def test_single_suspicious_mark_does_not_lock_down():
    ld = LockdownManager(suspicious_threshold_for_auto_lockdown=3)
    state = ld.mark_suspicious("one denied action")
    assert state == SecurityState.SUSPICIOUS
    assert not ld.is_locked_down()


def test_repeated_suspicious_marks_auto_escalate_to_lockdown():
    ld = LockdownManager(suspicious_threshold_for_auto_lockdown=2, suspicious_window_seconds=300)
    ld.mark_suspicious("first incident")
    state = ld.mark_suspicious("second incident")
    assert state == SecurityState.LOCKDOWN
    assert ld.is_locked_down()


def test_suspicious_marks_outside_window_do_not_accumulate():
    ld = LockdownManager(suspicious_threshold_for_auto_lockdown=2, suspicious_window_seconds=0.01)
    ld.mark_suspicious("first")
    import time
    time.sleep(0.05)
    state = ld.mark_suspicious("second, but window expired")
    assert state == SecurityState.SUSPICIOUS  # not LOCKDOWN -- first mark aged out
    assert not ld.is_locked_down()


def test_enter_lockdown_directly():
    ld = LockdownManager()
    state = ld.enter_lockdown("manual trigger for testing")
    assert state == SecurityState.LOCKDOWN
    assert ld.is_locked_down()


def test_exit_lockdown_requires_explicit_confirmation():
    ld = LockdownManager()
    ld.enter_lockdown("test")
    assert ld.exit_lockdown(user_confirmed=False) is False
    assert ld.is_locked_down()  # still locked down
    assert ld.exit_lockdown(user_confirmed=True) is True
    assert not ld.is_locked_down()
    assert ld.state == SecurityState.NORMAL


def test_exit_lockdown_when_not_locked_down_is_a_noop_returning_false():
    ld = LockdownManager()
    assert ld.exit_lockdown(user_confirmed=True) is False


def test_lockdown_allowed_tools_are_pure_diagnostics_only():
    # Nothing filesystem/project/network/execution-touching should ever be
    # in this set, regardless of future edits.
    forbidden_substrings = ("file", "project", "execute", "command", "open_", "search", "git", "docker", "python_env", "node_env")
    for tool_name in LOCKDOWN_ALLOWED_TOOLS:
        lowered = tool_name.lower()
        assert not any(s in lowered for s in forbidden_substrings), f"{tool_name} looks too broad for LOCKDOWN mode"


def test_is_tool_allowed_normal_state_allows_everything():
    ld = LockdownManager()
    assert ld.is_tool_allowed("execute_command") is True
    assert ld.is_tool_allowed("get_memory_usage") is True


def test_is_tool_allowed_lockdown_state_restricts_to_allowlist():
    ld = LockdownManager()
    ld.enter_lockdown("test")
    assert ld.is_tool_allowed("get_memory_usage") is True  # diagnostic, allowed
    assert ld.is_tool_allowed("execute_command") is False
    assert ld.is_tool_allowed("read_text_file") is False
    assert ld.is_tool_allowed("search_projects") is False
    assert ld.is_tool_allowed("open_folder") is False


def test_status_reports_history():
    ld = LockdownManager()
    ld.mark_suspicious("incident one")
    ld.enter_lockdown("incident two")
    status = ld.status()
    assert status["state"] == "LOCKDOWN"
    assert len(status["history"]) >= 2


def test_lockdown_is_audited():
    events = []

    class FakeAudit:
        def record(self, **kwargs):
            events.append(kwargs["event_type"])

    ld = LockdownManager(audit_sink=FakeAudit())
    ld.mark_suspicious("x")
    ld.enter_lockdown("y")
    ld.exit_lockdown(user_confirmed=True)
    assert "security_state_suspicious" in events
    assert "security_lockdown_entered" in events
    assert "security_lockdown_exited" in events


# -- end-to-end: LockdownManager actually gates the real PolicyEngine -------

def test_policy_engine_denies_everything_except_diagnostics_in_lockdown(settings, registry, audit_log):
    from jarvis.security.permissions import Decision
    from jarvis.security.policy_engine import PolicyEngine

    ld = LockdownManager()
    ld.enter_lockdown("test")
    engine = PolicyEngine(settings, registry.policy_specs(), audit_sink=audit_log, lockdown_manager=ld)

    from jarvis.security.permissions import ActionRequest
    project = settings.indexed_roots[0]

    # Diagnostic tool: still allowed.
    diag = engine.evaluate(ActionRequest(tool_name="get_memory_usage", args={}))
    assert diag.decision == Decision.ALLOW

    # Everything else, even a normally-harmless READ/SAFE tool: denied.
    for tool_name, kwargs in [
        ("search_projects", {"args": {"query": "x"}}),
        ("read_text_file", {"paths": [project]}),
        ("open_folder", {"paths": [project]}),
        ("execute_command", {"command": "git status", "cwd": project, "paths": [project]}),
    ]:
        req = ActionRequest(tool_name=tool_name, **kwargs)
        decision = engine.evaluate(req)
        assert decision.decision == Decision.DENY, f"{tool_name} should be denied during LOCKDOWN"


def test_policy_engine_normal_after_lockdown_is_exited(settings, registry, audit_log):
    from jarvis.security.permissions import ActionRequest, Decision
    from jarvis.security.policy_engine import PolicyEngine

    ld = LockdownManager()
    ld.enter_lockdown("test")
    engine = PolicyEngine(settings, registry.policy_specs(), audit_sink=audit_log, lockdown_manager=ld)

    ld.exit_lockdown(user_confirmed=True)
    decision = engine.evaluate(ActionRequest(tool_name="search_projects", args={"query": "x"}))
    assert decision.decision == Decision.ALLOW


def test_security_monitor_alert_feeds_lockdown_manager(settings, registry, audit_log):
    from jarvis.security.monitor import SecurityMonitor
    from jarvis.security.permissions import ActionRequest, Decision, PermissionLevel, PolicyDecision, RiskLevel

    ld = LockdownManager(suspicious_threshold_for_auto_lockdown=5)
    monitor = SecurityMonitor(audit_sink=audit_log, blocked_tool_threshold=2, lockdown_manager=ld)

    deny = PolicyDecision(Decision.DENY, PermissionLevel.DENY, RiskLevel.CRITICAL, ["x"])
    req = ActionRequest(tool_name="execute_command", command="bad", cwd="/tmp")
    monitor.observe(req, deny)
    monitor.observe(req, deny)  # crosses blocked_tool_threshold=2 -> alert -> mark_suspicious

    assert ld.state == SecurityState.SUSPICIOUS
