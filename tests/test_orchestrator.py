from __future__ import annotations

from jarvis.core.orchestrator import EntityState, Orchestrator
from jarvis.llm.ollama_client import ChatResponse, ToolCall
from jarvis.security.permissions import ApprovalScope


def make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, approval_callback=None):
    orch = Orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, approval_callback=approval_callback)
    orch.llm.is_available = lambda: True
    return orch


def test_read_tool_executes_without_approval(settings, registry, policy_engine, sandbox, audit_log, memory):
    calls = {"n": 0}

    def fake_chat(messages, tools=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return ChatResponse(content="", tool_calls=[ToolCall(id="1", name="get_memory_usage", arguments={})])
        return ChatResponse(content="done", tool_calls=[])

    def approval_should_not_be_called(request, decision):
        raise AssertionError("approval_callback must not be invoked for a READ-category tool")

    orch = make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, approval_should_not_be_called)
    orch.llm.chat = fake_chat

    events = list(orch.handle_message("how much ram am i using"))
    assert any(e.type == "assistant_text" and e.payload == "done" for e in events)
    assert any(e.type == "state" and e.payload == EntityState.SUCCESS for e in events)


def test_absolute_deny_never_invokes_approval_callback(settings, registry, policy_engine, sandbox, audit_log, memory):
    def fake_chat(messages, tools=None):
        if not fake_chat.called:
            fake_chat.called = True
            return ChatResponse(content="", tool_calls=[ToolCall(id="1", name="disable_windows_defender", arguments={})])
        return ChatResponse(content="I can't do that.", tool_calls=[])
    fake_chat.called = False

    def approval_should_not_be_called(request, decision):
        raise AssertionError("approval_callback must not be invoked for an absolute-deny tool")

    orch = make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, approval_should_not_be_called)
    orch.llm.chat = fake_chat

    events = list(orch.handle_message("disable my antivirus"))
    tool_results = [e.payload for e in events if e.type == "tool_result"]
    assert any(r["success"] is False for r in tool_results)


def test_destructive_action_is_gated_and_denial_is_respected(settings, registry, policy_engine, sandbox, audit_log, memory, tmp_path):
    project = settings.indexed_roots[0]
    approval_calls = []

    def fake_chat(messages, tools=None):
        if not fake_chat.called:
            fake_chat.called = True
            return ChatResponse(content="", tool_calls=[ToolCall(id="1", name="execute_command", arguments={"command": "rm -rf .", "cwd": project})])
        return ChatResponse(content="Understood, I did not delete anything.", tool_calls=[])
    fake_chat.called = False

    def deny_everything(request, decision):
        approval_calls.append((request.tool_name, decision.category))
        return ApprovalScope.DENY

    orch = make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, deny_everything)
    orch.llm.chat = fake_chat

    events = list(orch.handle_message("clean up this project"))
    assert len(approval_calls) == 1
    tool_results = [e.payload for e in events if e.type == "tool_result"]
    assert any(r["success"] is False and "denied" in (r.get("error") or "").lower() for r in tool_results)


def test_runaway_llm_loop_is_bounded(settings, registry, policy_engine, sandbox, audit_log, memory):
    # A model stuck proposing tool calls forever (or adversarially trying to
    # keep JARVIS running actions indefinitely) must not hang the turn.
    call_count = {"n": 0}

    def never_stopping_chat(messages, tools=None):
        call_count["n"] += 1
        return ChatResponse(content="", tool_calls=[ToolCall(id=str(call_count["n"]), name="get_memory_usage", arguments={})])

    orch = make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, lambda r, d: ApprovalScope.ONCE)
    orch.llm.chat = never_stopping_chat

    events = list(orch.handle_message("do something forever"))
    assert call_count["n"] <= 10  # bounded round-trips, not unbounded
    assert any(e.type == "error" for e in events)


def test_single_response_flood_of_tool_calls_is_capped(settings, registry, policy_engine, sandbox, audit_log, memory):
    # max_commands_per_request must hold even when all the calls arrive in
    # ONE LLM response, not just across multiple round-trips.
    settings.limits.max_commands_per_request = 5
    call_count = {"n": 0}

    def flood_chat(messages, tools=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return ChatResponse(content="", tool_calls=[ToolCall(id=str(i), name="get_memory_usage", arguments={}) for i in range(200)])
        return ChatResponse(content="done", tool_calls=[])

    orch = make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, lambda r, d: ApprovalScope.ONCE)
    orch.llm.chat = flood_chat

    events = list(orch.handle_message("do 200 things at once"))
    errors = [e.payload for e in events if e.type == "error"]
    assert any("limit" in str(e).lower() or "maximum" in str(e).lower() for e in errors)


def test_max_commands_per_request_limit_is_enforced(settings, registry, policy_engine, sandbox, audit_log, memory):
    settings.limits.max_commands_per_request = 2
    call_log = []

    def fake_chat(messages, tools=None):
        call_log.append(1)
        if len(call_log) <= 4:
            return ChatResponse(content="", tool_calls=[ToolCall(id=str(len(call_log)), name="get_memory_usage", arguments={})])
        return ChatResponse(content="done", tool_calls=[])

    orch = make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, lambda r, d: ApprovalScope.ONCE)
    orch.llm.chat = fake_chat

    events = list(orch.handle_message("check memory repeatedly"))
    errors = [e.payload for e in events if e.type == "error"]
    assert any("limit" in str(e).lower() or "maximum" in str(e).lower() for e in errors)


def test_emergency_stop_aborts_remaining_execution(settings, registry, policy_engine, sandbox, audit_log, memory):
    # Simulates the real scenario: the user hits the emergency-stop hotkey
    # (a separate thread calling orchestrator.emergency_stop(), independent
    # of the LLM) WHILE a multi-step turn is mid-flight -- here, while the
    # approval dialog for the first of two proposed actions is being
    # answered. The second action must never run.
    project = settings.indexed_roots[0]

    def fake_chat(messages, tools=None):
        # Destructive-classified but harmless to actually run: targets a
        # path that doesn't exist, so the first (already-approved) action
        # executing for real in this test doesn't touch anything.
        return ChatResponse(content="", tool_calls=[
            ToolCall(id="1", name="execute_command", arguments={"command": "rm -rf ./no_such_marker_dir", "cwd": project}),
            ToolCall(id="2", name="execute_command", arguments={"command": "rm -rf ./another_no_such_dir", "cwd": project}),
        ])

    def approve_then_trigger_stop(request, decision):
        orch._stop_event.set()  # simulates the hotkey firing concurrently
        return ApprovalScope.ONCE

    orch = make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, approve_then_trigger_stop)
    orch.llm.chat = fake_chat

    events = list(orch.handle_message("clean up"))
    assert any(e.type == "error" and "emergency stop" in str(e.payload).lower() for e in events)
    approval_events = [e for e in events if e.type == "approval_request"]
    assert len(approval_events) == 1  # the second action was never reached


def test_missing_required_argument_does_not_crash_the_turn(settings, registry, policy_engine, sandbox, audit_log, memory):
    # Found by stress testing: a tool call missing a required argument
    # (list_directory needs "path") raised an uncaught KeyError straight out
    # of tool.execute(), which would have propagated out of the whole
    # handle_message generator on the orchestrator's background thread.
    def fake_chat(messages, tools=None):
        if not fake_chat.called:
            fake_chat.called = True
            return ChatResponse(content="", tool_calls=[ToolCall(id="1", name="list_directory", arguments={})])
        return ChatResponse(content="handled", tool_calls=[])
    fake_chat.called = False

    orch = make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, lambda r, d: ApprovalScope.ONCE)
    orch.llm.chat = fake_chat

    events = list(orch.handle_message("list a directory"))  # must not raise
    tool_results = [e.payload for e in events if e.type == "tool_result"]
    assert any(r["success"] is False for r in tool_results)
    assert any(e.type == "assistant_text" and e.payload == "handled" for e in events)


def test_non_dict_tool_arguments_does_not_crash_the_turn(settings, registry, policy_engine, sandbox, audit_log, memory):
    # Found by stress testing: some models return tool-call arguments as a
    # plain string or other non-object shape instead of a JSON object.
    def fake_chat(messages, tools=None):
        if not fake_chat.called:
            fake_chat.called = True
            return ChatResponse(content="", tool_calls=[ToolCall(id="1", name="list_directory", arguments="not a dict")])
        return ChatResponse(content="handled", tool_calls=[])
    fake_chat.called = False

    orch = make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, lambda r, d: ApprovalScope.ONCE)
    orch.llm.chat = fake_chat

    events = list(orch.handle_message("list a directory"))  # must not raise
    tool_results = [e.payload for e in events if e.type == "tool_result"]
    assert any(r["success"] is False for r in tool_results)


def test_session_grant_avoids_repeated_approval_within_session(settings, registry, policy_engine, sandbox, audit_log, memory):
    project = settings.indexed_roots[0]
    approval_calls = []

    def fake_chat(messages, tools=None):
        n = sum(1 for m in messages if m.get("role") == "tool")
        if n < 2:
            return ChatResponse(content="", tool_calls=[ToolCall(id=str(n), name="execute_command", arguments={"command": "pip install requests", "cwd": project})])
        return ChatResponse(content="done", tool_calls=[])

    def approve_session_once(request, decision):
        approval_calls.append(request.grant_key)
        return ApprovalScope.SESSION

    orch = make_orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, approve_session_once)
    orch.llm.chat = fake_chat

    list(orch.handle_message("install requests"))
    list(orch.handle_message("install requests again"))

    # Second identical action should be covered by the session grant from the
    # first turn and not prompt for approval a second time.
    assert len(approval_calls) == 1
