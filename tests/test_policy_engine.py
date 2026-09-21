from __future__ import annotations

from jarvis.security.permissions import ActionRequest, Decision, PermissionLevel


def test_absolute_deny_tool_blocked(policy_engine):
    decision = policy_engine.evaluate(ActionRequest(tool_name="disable_windows_defender", args={}))
    assert decision.decision == Decision.DENY
    assert decision.absolute is True


def test_grant_admin_privileges_blocked(policy_engine):
    decision = policy_engine.evaluate(ActionRequest(tool_name="grant_admin_privileges", args={}))
    assert decision.decision == Decision.DENY


def test_read_ssh_key_path_denied(policy_engine, settings):
    path = str(__import__("pathlib").Path.home() / ".ssh" / "id_rsa")
    decision = policy_engine.evaluate(ActionRequest(tool_name="read_text_file", paths=[path]))
    assert decision.decision == Decision.DENY


def test_browser_cookie_path_denied(policy_engine):
    decision = policy_engine.evaluate(ActionRequest(tool_name="read_text_file", paths=["C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"]))
    assert decision.decision == Decision.DENY


def test_system_root_denied(policy_engine):
    decision = policy_engine.evaluate(ActionRequest(tool_name="list_directory", paths=["C:\\Windows\\System32"]))
    assert decision.decision == Decision.DENY


def test_read_tool_allowed(policy_engine):
    decision = policy_engine.evaluate(ActionRequest(tool_name="get_memory_usage", args={}))
    assert decision.decision == Decision.ALLOW
    assert decision.category == PermissionLevel.READ


def test_safe_tool_allowed(policy_engine):
    decision = policy_engine.evaluate(ActionRequest(tool_name="search_projects", args={"query": "x"}))
    assert decision.decision == Decision.ALLOW
    assert decision.category == PermissionLevel.SAFE


def test_unknown_tool_fails_closed(policy_engine):
    decision = policy_engine.evaluate(ActionRequest(tool_name="totally_made_up_tool", args={}))
    assert decision.decision == Decision.DENY
    assert decision.category == PermissionLevel.DENY


def test_self_protection_blocks_security_dir_writes(policy_engine):
    decision = policy_engine.evaluate(ActionRequest(tool_name="execute_command", command="echo hi", cwd="/some/path/jarvis/security/x", paths=["/some/path/jarvis/security/x"]))
    assert decision.decision == Decision.DENY


def test_self_protection_blocks_audit_db(policy_engine):
    decision = policy_engine.evaluate(ActionRequest(tool_name="execute_command", command="del audit.db", paths=["C:\\data\\audit.db"]))
    assert decision.decision == Decision.DENY


def test_destructive_command_requires_confirm_not_silent_deny(policy_engine, settings):
    project = settings.indexed_roots[0]
    decision = policy_engine.evaluate(ActionRequest(tool_name="execute_command", command="rm -rf .", cwd=project, paths=[project]))
    # Dangerous but not on the absolute deny list -> gated, not silently blocked or silently run.
    assert decision.decision == Decision.CONFIRM
    assert decision.category == PermissionLevel.DESTRUCTIVE


def test_disable_defender_command_is_absolute_deny(policy_engine, settings):
    project = settings.indexed_roots[0]
    decision = policy_engine.evaluate(ActionRequest(tool_name="execute_command", command="Set-MpPreference -DisableRealtimeMonitoring $true", cwd=project, paths=[project]))
    assert decision.decision == Decision.DENY


def test_git_status_read_only_allowed(policy_engine, settings):
    project = settings.indexed_roots[0]
    decision = policy_engine.evaluate(ActionRequest(tool_name="execute_command", command="git status", cwd=project, paths=[project]))
    assert decision.decision == Decision.ALLOW
    assert decision.category == PermissionLevel.READ


def test_modify_grant_allows_repeat_action(policy_engine, settings):
    project = settings.indexed_roots[0]

    class FakeGrants:
        def __init__(self):
            self.granted = set()

        def has_grant(self, key):
            return key in self.granted

    grants = FakeGrants()
    policy_engine.grant_store = grants

    req = ActionRequest(tool_name="execute_command", command="pip install requests", cwd=project, paths=[project], grant_key="execute_command:pip:proj")
    first = policy_engine.evaluate(req)
    assert first.decision == Decision.CONFIRM

    grants.granted.add("execute_command:pip:proj")
    second = policy_engine.evaluate(req)
    assert second.decision == Decision.ALLOW


def test_destructive_never_covered_by_grant(policy_engine, settings):
    project = settings.indexed_roots[0]

    class AllGrants:
        def has_grant(self, key):
            return True  # pretend everything is pre-approved

    policy_engine.grant_store = AllGrants()
    req = ActionRequest(tool_name="execute_command", command="rm -rf .", cwd=project, paths=[project], grant_key="execute_command:rm:proj")
    decision = policy_engine.evaluate(req)
    # Even with a grant store that approves everything, DESTRUCTIVE must still CONFIRM.
    assert decision.decision == Decision.CONFIRM
    assert decision.category == PermissionLevel.DESTRUCTIVE
