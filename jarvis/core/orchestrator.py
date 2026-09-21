"""The orchestrator implements exactly one loop, and implements it literally:

    LLM -> intent -> tool request -> policy engine -> permission check
        -> execution layer -> result -> LLM

Every tool call the model proposes is converted to an ActionRequest, sent to
the PolicyEngine (which never consults the LLM), and only executed if the
decision is ALLOW, or CONFIRM followed by a real approval callback response.
The orchestrator itself holds no security logic -- it cannot decide an
action is safe, it can only ask the policy engine and act on the answer.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterator

from jarvis.core import context as context_builder
from jarvis.core.planner import build_plan
from jarvis.llm.ollama_client import ChatResponse, OllamaClient, OllamaUnavailableError, ToolCall
from jarvis.llm.prompts import SYSTEM_PROMPT, build_context_block
from jarvis.security.permissions import ActionRequest, ApprovalScope, Decision, PolicyDecision
from jarvis.security.policy_engine import PolicyEngine
from jarvis.tools.base import ToolContext
from jarvis.tools.registry import ToolRegistry


class EntityState(str, Enum):
    IDLE = "IDLE"
    LISTENING = "LISTENING"
    THINKING = "THINKING"
    SEARCHING = "SEARCHING"
    EXECUTING = "EXECUTING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"


@dataclass
class OrchestratorEvent:
    type: str  # "state" | "plan" | "tool_call" | "tool_result" | "approval_request" | "assistant_text" | "error"
    payload: Any = None


ApprovalCallback = Callable[[ActionRequest, PolicyDecision], ApprovalScope]


def _default_deny_callback(request: ActionRequest, decision: PolicyDecision) -> ApprovalScope:
    return ApprovalScope.CANCEL


class EmergencyStop(Exception):
    pass


class Orchestrator:
    def __init__(
        self,
        settings,
        registry: ToolRegistry,
        policy_engine: PolicyEngine,
        sandbox,
        audit_log,
        memory,
        llm_client: OllamaClient | None = None,
        approval_callback: ApprovalCallback | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.policy_engine = policy_engine
        self.sandbox = sandbox
        self.audit_log = audit_log
        self.memory = memory
        self.llm = llm_client or OllamaClient(settings)
        self.approval_callback = approval_callback or _default_deny_callback
        self._project_index: list | None = None
        self._stop_event = threading.Event()

    # -- lifecycle -----------------------------------------------------------

    def refresh_project_index(self, force: bool = False) -> list:
        from jarvis.tools.project_tools import ProjectRecord, build_index
        from dataclasses import asdict

        if not force:
            cached = self.memory.load_project_index() if self.memory else None
            if cached is not None:
                self._project_index = [ProjectRecord(**r) for r in cached]
                return self._project_index
        records = build_index(self.settings)
        self._project_index = records
        if self.memory:
            self.memory.save_project_index([asdict(r) for r in records])
        return records

    def emergency_stop(self) -> int:
        """Independent of the LLM: called directly from the UI's global hotkey
        handler. Sets a flag the running loop checks between steps and kills
        every active sandboxed subprocess immediately."""
        self._stop_event.set()
        killed = self.sandbox.emergency_stop_all() if self.sandbox else 0
        if self.audit_log:
            self.audit_log.record(event_type="emergency_stop", processes_killed=killed)
        return killed

    def reset_stop(self) -> None:
        self._stop_event.clear()

    # -- main loop -------------------------------------------------------------

    def handle_message(self, user_text: str) -> Iterator[OrchestratorEvent]:
        self.reset_stop()
        if self.memory:
            self.memory.add_message("user", user_text)

        yield OrchestratorEvent("state", EntityState.THINKING)

        if not self.llm.is_available():
            msg = (f"I can't reach the local LLM at {self.settings.llm_host}. "
                   f"Start Ollama ('ollama serve') and make sure '{self.settings.llm_model}' is pulled.")
            yield OrchestratorEvent("error", msg)
            yield OrchestratorEvent("state", EntityState.ERROR)
            return

        messages = self._build_messages(user_text)
        commands_this_turn = 0
        max_commands = self.settings.limits.max_commands_per_request

        try:
            for _ in range(6):  # bounded tool-call round trips per user turn
                if self._stop_event.is_set():
                    raise EmergencyStop()

                try:
                    response = self.llm.chat(messages, tools=self.registry.llm_schemas())
                except OllamaUnavailableError as exc:
                    yield OrchestratorEvent("error", str(exc))
                    yield OrchestratorEvent("state", EntityState.ERROR)
                    return

                if not response.tool_calls:
                    text = response.content.strip()
                    if self.memory:
                        self.memory.add_message("assistant", text)
                    yield OrchestratorEvent("assistant_text", text)
                    yield OrchestratorEvent("state", EntityState.SUCCESS)
                    return

                messages.append({"role": "assistant", "content": response.content, "tool_calls": self._raw_tool_calls(response)})

                if len(response.tool_calls) > 1:
                    yield OrchestratorEvent("state", EntityState.THINKING)
                    plan_items = [self._evaluate_call(tc) for tc in response.tool_calls]
                    plan = build_plan(plan_items)
                    yield OrchestratorEvent("plan", plan.render())

                for tool_call in response.tool_calls:
                    if self._stop_event.is_set():
                        raise EmergencyStop()

                    if commands_this_turn >= max_commands:
                        result_text = (f"Stopped: this request would run more than the configured limit "
                                        f"of {max_commands} actions in one turn. Nothing further was executed.")
                        yield OrchestratorEvent("error", result_text)
                        messages.append(self._tool_result_message(tool_call, {"success": False, "error": result_text}))
                        continue

                    tool = self.registry.get(tool_call.name)
                    if tool is None:
                        result = {"success": False, "error": f"Unknown tool '{tool_call.name}'."}
                        yield OrchestratorEvent("tool_result", result)
                        messages.append(self._tool_result_message(tool_call, result))
                        continue

                    if not isinstance(tool_call.arguments, dict):
                        # Defense in depth: OllamaClient already normalizes
                        # arguments to a dict, but nothing upstream of this
                        # loop is trusted to guarantee that shape.
                        result = {"success": False, "error": f"Malformed arguments for '{tool_call.name}' (expected an object)."}
                        yield OrchestratorEvent("tool_result", result)
                        messages.append(self._tool_result_message(tool_call, result))
                        continue

                    request = tool.build_request(tool_call.arguments)
                    request.request_id = tool_call.id
                    decision = self.policy_engine.evaluate(request)
                    yield OrchestratorEvent("tool_call", {"tool": tool.name, "args": tool_call.arguments, "decision": decision})

                    outcome = self._handle_decision(tool, tool_call.arguments, request, decision)
                    for event in outcome.events:
                        yield event
                    if outcome.executed:
                        commands_this_turn += 1

                    messages.append(self._tool_result_message(tool_call, outcome.result_dict))

            yield OrchestratorEvent("error", "Reached the maximum number of reasoning steps for this request.")
            yield OrchestratorEvent("state", EntityState.ERROR)

        except EmergencyStop:
            yield OrchestratorEvent("error", "Emergency stop engaged. All actions cancelled.")
            yield OrchestratorEvent("state", EntityState.IDLE)

    # -- helpers -----------------------------------------------------------

    def _build_messages(self, user_text: str) -> list[dict]:
        ctx = context_builder.build_context(self.settings, self._project_index, self.sandbox)
        system = SYSTEM_PROMPT + "\n\n" + build_context_block(ctx)
        messages: list[dict] = [{"role": "system", "content": system}]
        if self.memory:
            for m in self.memory.recent_messages(limit=12):
                if m.role in ("user", "assistant"):
                    messages.append({"role": m.role, "content": m.content})
        messages.append({"role": "user", "content": user_text})
        return messages

    def _raw_tool_calls(self, response: ChatResponse) -> list[dict]:
        return [{"id": tc.id, "function": {"name": tc.name, "arguments": tc.arguments}} for tc in response.tool_calls]

    def _tool_result_message(self, tool_call: ToolCall, result: dict) -> dict:
        return {"role": "tool", "tool_call_id": tool_call.id, "content": json.dumps(result, default=str)[:6000]}

    def _evaluate_call(self, tool_call: ToolCall) -> tuple[ActionRequest, PolicyDecision]:
        tool = self.registry.get(tool_call.name)
        if tool is None:
            req = ActionRequest(tool_name=tool_call.name, args=tool_call.arguments, description=f"Unknown tool {tool_call.name}")
            from jarvis.security.permissions import PermissionLevel, RiskLevel
            return req, PolicyDecision(Decision.DENY, PermissionLevel.DENY, RiskLevel.CRITICAL, ["Unknown tool."], absolute=True)
        req = tool.build_request(tool_call.arguments)
        return req, self.policy_engine.evaluate(req)

    @dataclass
    class _Outcome:
        events: list[OrchestratorEvent] = field(default_factory=list)
        result_dict: dict = field(default_factory=dict)
        executed: bool = False

    def _handle_decision(self, tool, args: dict, request: ActionRequest, decision: PolicyDecision) -> "Orchestrator._Outcome":
        out = Orchestrator._Outcome()

        if decision.decision == Decision.DENY:
            reason = "; ".join(decision.reasons)
            out.result_dict = {"success": False, "error": f"Denied by policy: {reason}"}
            out.events.append(OrchestratorEvent("tool_result", out.result_dict))
            if self.memory:
                self.memory.record_action(request.description or request.tool_name, "DENIED")
            return out

        if decision.decision == Decision.CONFIRM:
            out.events.append(OrchestratorEvent("state", EntityState.WAITING_FOR_APPROVAL))
            out.events.append(OrchestratorEvent("approval_request", {"request": request, "decision": decision}))
            scope = self.approval_callback(request, decision)

            if scope in (ApprovalScope.DENY, ApprovalScope.CANCEL):
                out.result_dict = {"success": False, "error": "User denied this action. Nothing was changed."}
                out.events.append(OrchestratorEvent("tool_result", out.result_dict))
                if self.memory:
                    self.memory.record_action(request.description or request.tool_name, "DENIED_BY_USER")
                return out

            from jarvis.security.permissions import PermissionLevel
            if request.grant_key and decision.category != PermissionLevel.DESTRUCTIVE:
                if scope == ApprovalScope.SESSION:
                    self.memory.add_session_grant(request.grant_key) if self.memory else None
                elif scope == ApprovalScope.ALWAYS_THIS_ACTION:
                    self.memory.add_permanent_grant(request.grant_key) if self.memory else None

        out.events.append(OrchestratorEvent("state", EntityState.EXECUTING))
        context = ToolContext(settings=self.settings, sandbox=self.sandbox, memory=self.memory, project_index=self._project_index)
        try:
            result = tool.execute(args, context)
        except Exception as exc:
            # A malformed tool call (e.g. the model omitting a required
            # argument) must never crash the turn -- it must be reported the
            # same as any other tool failure: nothing was changed, here is
            # why. Without this, an uncaught exception here would propagate
            # out of the whole handle_message generator mid-turn, on the
            # background thread, leaving the UI stuck in EXECUTING with the
            # chat input disabled forever (turn_finished never emitted).
            from jarvis.tools.base import ToolResult
            error_msg = f"{type(exc).__name__}: {exc}"
            result = ToolResult(False, error=error_msg, facts=[f"I couldn't complete that operation.\nReason: {error_msg}\nNothing was changed."])
        out.executed = True
        out.result_dict = {"success": result.success, "data": result.data, "error": result.error, "facts": result.facts}
        out.events.append(OrchestratorEvent("tool_result", out.result_dict))

        if self.audit_log:
            self.audit_log.record(
                event_type="tool_execution", tool=tool.name, args=args,
                success=result.success, error=result.error,
            )
        if self.memory:
            self.memory.record_action(request.description or tool.name, "SUCCESS" if result.success else "FAILED")

        return out
