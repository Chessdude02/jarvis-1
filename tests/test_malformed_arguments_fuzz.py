"""Every registered tool, hit with every malformed argument shape, through
the FULL orchestrator loop (not just each function in isolation). Found via
this exact fuzz sweep: build_request() and PolicyEngine.evaluate() ran
unprotected between the "unknown tool" check and the tool.execute() guard,
so a non-string value in a path/command/cwd argument (a model returning
null, a number, or a list where a string was expected) could raise deep
inside PolicyEngine._check_self_protection, deny_list.denied_path, or a
tool's own build_request() -- and that exception propagated out of the
whole handle_message generator on the orchestrator's background thread.

Fixed at two levels: PolicyEngine._evaluate() now sanitizes
paths/cwd/command to their declared types before any check runs, and
Orchestrator.handle_message() wraps build_request()+evaluate() in the same
try/except pattern already used around tool.execute(), so nothing upstream
of tool.execute() can crash the turn either, regardless of which specific
internal function has the next latent type-assumption bug.
"""
from __future__ import annotations

from jarvis.core.orchestrator import Orchestrator
from jarvis.llm.ollama_client import ChatResponse, ToolCall
from jarvis.security.permissions import ApprovalScope

_FUZZ_ARG_SETS = [
    {}, {"path": None}, {"path": 12345}, {"path": ["a", "list"]}, {"path": {"n": "d"}},
    {"path": ""}, {"path": " " * 300},
    {"command": None, "cwd": None}, {"command": 123, "cwd": 456}, {"command": "", "cwd": ""},
    {"query": None}, {"query": 999}, {"text": None}, {"pattern": None}, {"name_filter": 123},
    {"app_name": None}, {"execution_id": None}, {"execution_id": 123},
    {"limit": "not a number"}, {"limit": -999999999}, {"limit": float("inf")},
    {"root": 123}, {"explanation": None, "command": None},
]


def test_every_tool_survives_every_malformed_argument_shape(settings, registry, policy_engine, sandbox, audit_log, memory):
    failures = []

    for tool in registry.all():
        for args in _FUZZ_ARG_SETS:
            orch = Orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory,
                                 approval_callback=lambda r, d: ApprovalScope.ONCE)
            orch.llm.is_available = lambda: True
            call_state = {"n": 0}

            def fake_chat(messages, tools=None, _tool=tool, _args=args):
                call_state["n"] += 1
                if call_state["n"] == 1:
                    return ChatResponse(content="", tool_calls=[ToolCall(id="1", name=_tool.name, arguments=_args)])
                return ChatResponse(content="done", tool_calls=[])

            orch.llm.chat = fake_chat
            try:
                events = list(orch.handle_message(f"fuzz {tool.name}"))
            except Exception as e:
                failures.append(f"{tool.name}({args!r}) raised {type(e).__name__}: {e}")
                continue
            if not any(e.type in ("assistant_text", "error") for e in events):
                failures.append(f"{tool.name}({args!r}) produced no terminal event (turn never ends)")

    assert not failures, "malformed-argument fuzzing found crashes:\n" + "\n".join(failures[:20])
