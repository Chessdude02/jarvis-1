"""The approval card must show whether an action can be undone, not just its
risk level. Reversibility is a judgment call made by deterministic code
(the command classifier, or the policy engine's per-category default), never
by the LLM claiming its own action is safe/undoable.
"""
from __future__ import annotations

from jarvis.security.command_validator import classify_command
from jarvis.security.permissions import ActionRequest, PermissionLevel, Reversibility


def test_recursive_delete_is_irreversible():
    assert classify_command("rm -rf build/").reversibility == Reversibility.IRREVERSIBLE


def test_git_reset_hard_is_irreversible():
    assert classify_command("git reset --hard HEAD~3").reversibility == Reversibility.IRREVERSIBLE


def test_format_drive_is_irreversible():
    assert classify_command("format d: /q").reversibility == Reversibility.IRREVERSIBLE


def test_shutdown_is_partially_reversible():
    assert classify_command("shutdown /s /t 0").reversibility == Reversibility.PARTIALLY_REVERSIBLE


def test_taskkill_force_is_partially_reversible():
    assert classify_command("taskkill /f /pid 1234").reversibility == Reversibility.PARTIALLY_REVERSIBLE


def test_pip_install_is_reversible():
    assert classify_command("pip install requests").reversibility == Reversibility.REVERSIBLE


def test_read_only_command_is_reversible():
    assert classify_command("git status").reversibility == Reversibility.REVERSIBLE


def test_unknown_shape_reversibility_is_unknown_not_assumed_safe():
    result = classify_command("frobnicate --whatever /dev/sda")
    assert result.reversibility == Reversibility.UNKNOWN


def test_policy_engine_sets_reversibility_on_the_request(policy_engine, settings):
    project = settings.indexed_roots[0]
    request = ActionRequest(tool_name="execute_command", command="rm -rf .", cwd=project, paths=[project])
    assert request.reversibility == Reversibility.UNKNOWN  # not yet evaluated
    policy_engine.evaluate(request)
    assert request.reversibility == Reversibility.IRREVERSIBLE  # set as a side effect of evaluation


def test_policy_engine_sets_reversibility_for_non_command_tools(policy_engine):
    request = ActionRequest(tool_name="get_memory_usage", args={})
    policy_engine.evaluate(request)
    assert request.reversibility == Reversibility.REVERSIBLE

    request2 = ActionRequest(tool_name="open_folder", args={"path": "x"})
    policy_engine.evaluate(request2)
    assert request2.reversibility == Reversibility.REVERSIBLE
