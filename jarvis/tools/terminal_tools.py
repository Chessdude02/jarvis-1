"""Terminal-assistant tools. execute_command is the one tool in this codebase
that runs arbitrary shell text, which is exactly why it's the most guarded:
is_command_tool=True routes it through command_validator instead of a fixed
category, so its actual ALLOW/CONFIRM/DENY depends on what the command
actually is, not on trusting the LLM's framing of it.
"""
from __future__ import annotations

from jarvis.security.command_validator import classify_command, grant_scope_for_command
from jarvis.security.permissions import PermissionLevel
from jarvis.security.secrets import redact
from jarvis.tools import path_guard
from jarvis.tools.base import Tool, ToolContext, ToolResult


class ProposeCommandTool(Tool):
    name = "propose_command"
    category = PermissionLevel.READ
    description = "Classify a candidate shell command's risk WITHOUT running it. Always call this before execute_command so the user sees risk before approval."
    parameters = {
        "type": "object",
        "properties": {"command": {"type": "string"}, "explanation": {"type": "string", "description": "Plain-language explanation of what the command does."}},
        "required": ["command", "explanation"],
    }

    def execute(self, args, context: ToolContext) -> ToolResult:
        cls = classify_command(args["command"])
        data = {
            "command": args["command"],
            "explanation": args["explanation"],
            "category": cls.category.value,
            "risk": cls.risk.value,
            "reversibility": cls.reversibility.value,
            "reasons": cls.reasons,
            "requires_approval": cls.category != PermissionLevel.READ,
        }
        facts = [
            f"Command: {args['command']}",
            f"Risk: {cls.risk.value} ({cls.category.value}).",
            f"Reversibility: {cls.reversibility.value}.",
        ] + cls.reasons
        return ToolResult(True, data, facts=facts)


class ExecuteCommandTool(Tool):
    name = "execute_command"
    category = PermissionLevel.MODIFY  # actual category is decided per-command by the policy engine
    is_command_tool = True
    description = "Execute an approved shell command in a specific working directory, inside the sandbox (timeout + output-size limited)."
    parameters = {
        "type": "object",
        "properties": {
            "command": {"type": "string"},
            "cwd": {"type": "string", "description": "Absolute working directory; must be inside a configured indexed root."},
        },
        "required": ["command", "cwd"],
    }

    def build_request(self, args):
        req = super().build_request(args)
        # Coerce to str explicitly rather than args.get("command", "") --
        # that default only applies when the key is ABSENT; a model
        # returning {"command": null} or {"command": 123} (found by
        # fuzzing) leaves the raw non-string value in place, which then
        # crashes .split() below.
        raw_command = args.get("command")
        raw_cwd = args.get("cwd")
        req.command = raw_command if isinstance(raw_command, str) else ""
        req.cwd = raw_cwd if isinstance(raw_cwd, str) else ""
        req.paths = [req.cwd]
        req.description = f"Run `{req.command}` in {req.cwd}"
        # grant_scope_for_command() returns the routine-action family (e.g.
        # "git add", not just "git") -- see its docstring for why a bare
        # first-token key was a real scope-creep bug: it let approving one
        # git/pip/npm subcommand silently cover a different, unreviewed one
        # for the rest of the session.
        req.grant_key = f"execute_command:{grant_scope_for_command(req.command) if req.command else ''}:{req.cwd}"
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        cwd = args["cwd"]
        err = path_guard.check_readable(cwd, context.settings)
        if err:
            return ToolResult(False, error=err, facts=[f"I refused to run that: {err}"])
        if context.sandbox is None:
            return ToolResult(False, error="Sandbox unavailable.", facts=["I could not execute the command: no sandbox is configured."])
        result = context.sandbox.run(args["command"], cwd)
        if result.error:
            return ToolResult(False, error=result.error, facts=[f"I couldn't complete that operation.\nReason: {result.error}\nNothing was changed."])
        # Redact BEFORE this output becomes a fact string or a data field --
        # this is what the chat UI displays live and what goes back into the
        # LLM's own context, not just what the audit log stores. A build
        # script that prints an API key must not surface it either place.
        stdout = redact(result.stdout)
        stderr = redact(result.stderr)
        # The command string itself can carry a secret (e.g. a bearer token
        # in a curl -H argument). The approval card the user saw before
        # execution showed it in full -- they need that to know exactly
        # what they're approving -- but this post-execution report feeds
        # back into chat history and the LLM's own context, so it gets the
        # same redaction as stdout/stderr here.
        facts = [
            f"Command: {redact(args['command'])}",
            f"Exit code: {result.return_code}{' (TIMED OUT, process was killed)' if result.timed_out else ''}",
        ]
        if result.truncated:
            facts.append("Output was truncated at the configured output-size limit.")
        if stdout.strip():
            facts.append("stdout:\n" + stdout[-4000:])
        if stderr.strip():
            facts.append("stderr:\n" + stderr[-4000:])
        success = (result.return_code == 0) and not result.timed_out
        return ToolResult(success, {
            "execution_id": result.execution_id,
            "return_code": result.return_code,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": result.timed_out,
            "truncated": result.truncated,
            "duration_seconds": result.duration_seconds,
        }, facts=facts)


class MonitorCommandTool(Tool):
    name = "monitor_command"
    category = PermissionLevel.READ
    description = "Check whether a previously started command execution is still running."
    parameters = {"type": "object", "properties": {"execution_id": {"type": "string"}}, "required": ["execution_id"]}

    def execute(self, args, context: ToolContext) -> ToolResult:
        if context.sandbox is None:
            return ToolResult(False, error="Sandbox unavailable.")
        running = args["execution_id"] in getattr(context.sandbox, "_active", {})
        return ToolResult(True, {"running": running}, facts=[f"Execution {args['execution_id']} is {'still running' if running else 'not currently running'}."])


class TerminateCommandTool(Tool):
    name = "terminate_command"
    category = PermissionLevel.SAFE
    description = "Forcibly stop a running command execution started by execute_command."
    parameters = {"type": "object", "properties": {"execution_id": {"type": "string"}}, "required": ["execution_id"]}

    def execute(self, args, context: ToolContext) -> ToolResult:
        if context.sandbox is None:
            return ToolResult(False, error="Sandbox unavailable.")
        ok = context.sandbox.terminate(args["execution_id"])
        return ToolResult(ok, {"terminated": ok}, facts=[f"Execution {args['execution_id']} {'was terminated' if ok else 'was not found running'}."])


TOOLS = [ProposeCommandTool(), ExecuteCommandTool(), MonitorCommandTool(), TerminateCommandTool()]
