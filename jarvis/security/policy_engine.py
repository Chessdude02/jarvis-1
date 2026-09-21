"""The single place that turns an ActionRequest into a Decision.

This is the deterministic authority the spec calls for: the LLM proposes,
this module disposes. It never calls the LLM and never imports it. Every
public method here is a pure function of (request, settings, grants) so it
can be exhaustively unit-tested without a model, a UI, or a subprocess.

Order of checks (first match wins):
  1. Absolute deny list (tool name, path fragments, command patterns).
  2. Self-protection (nothing may touch jarvis/security/, jarvis/config/,
     the audit DB, or its own source/executable).
  3. System deny roots from config (Windows/Program Files/credential dirs).
  4. Category resolution: READ/SAFE -> ALLOW; MODIFY -> CONFIRM (or ALLOW if
     covered by a live grant); DESTRUCTIVE -> CONFIRM, always, no grant can
     pre-approve it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol

from jarvis.security import deny_list
from jarvis.security.command_validator import classify_command
from jarvis.security.lockdown import LockdownManager
from jarvis.security.monitor import SecurityMonitor
from jarvis.security.permissions import (
    ActionRequest,
    Decision,
    PermissionLevel,
    PolicyDecision,
    Reversibility,
    RiskLevel,
)

# Paths inside the repo/install that JARVIS must never be asked to write to,
# regardless of tool. Resolved relative to this file's package root.
_SELF_PROTECTED_SUBSTRINGS = (
    os.sep + "jarvis" + os.sep + "security" + os.sep,
    os.sep + "jarvis" + os.sep + "config" + os.sep + "default_config.yaml",
    "audit.db",
)


class GrantStore(Protocol):
    """Anything that can answer 'has the user already approved this exact,
    narrow action for the current session or permanently?'. memory.py
    provides the real implementation; tests use a dict-backed fake.
    """

    def has_grant(self, grant_key: str) -> bool: ...


class AuditSink(Protocol):
    def record(self, **event) -> None: ...


@dataclass
class ToolSpec:
    name: str
    base_category: PermissionLevel
    # True for tools whose execution touches the real filesystem/process
    # table via a shell command string (routed through command_validator).
    is_command_tool: bool = False


class PolicyEngine:
    def __init__(
        self,
        settings,
        tool_registry: dict[str, ToolSpec] | None = None,
        grant_store: Optional[GrantStore] = None,
        audit_sink: Optional[AuditSink] = None,
        security_monitor: Optional[SecurityMonitor] = None,
        kill_switch=None,
        lockdown_manager: Optional[LockdownManager] = None,
    ) -> None:
        self.settings = settings
        self.tool_registry = tool_registry or {}
        self.grant_store = grant_store
        self.audit_sink = audit_sink
        self.security_monitor = security_monitor
        self.kill_switch = kill_switch
        self.lockdown_manager = lockdown_manager

    # -- public API -----------------------------------------------------

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        """Never raises. Per the fail-closed invariant ("policy engine
        unavailable" / "audit system unavailable" -> DO NOT EXECUTE): if
        anything in the decision or audit path breaks, the answer is an
        explicit DENY with a clear reason, not an exception a caller might
        mishandle or a decision that silently goes unaudited. This makes
        fail-closed a guarantee of this method itself, not something that
        happens to work only because whatever calls evaluate() has its own
        try/except around it.
        """
        try:
            decision = self._evaluate(request)
        except Exception as exc:
            decision = PolicyDecision(
                Decision.DENY, PermissionLevel.DENY, RiskLevel.CRITICAL,
                [f"Security policy evaluation failed ({type(exc).__name__}: {exc}); failing closed."],
                absolute=True,
            )

        if self.audit_sink is not None:
            try:
                self.audit_sink.record(
                    event_type="policy_decision",
                    tool=request.tool_name,
                    args=request.args,
                    command=request.command,
                    paths=request.paths,
                    decision=decision.decision.value,
                    category=decision.category.value,
                    risk=decision.risk.value,
                    reasons=decision.reasons,
                )
            except Exception as exc:
                # An otherwise-ALLOW decision that can't be written to the
                # audit log must not go through un-audited -- an action
                # nobody can prove happened is treated the same as one
                # that was never authorized.
                decision = PolicyDecision(
                    Decision.DENY, PermissionLevel.DENY, RiskLevel.CRITICAL,
                    [f"Audit log unavailable ({type(exc).__name__}: {exc}); refusing to proceed unaudited."],
                    absolute=True,
                )

        if self.security_monitor is not None:
            try:
                self.security_monitor.observe(request, decision)
            except Exception:
                # The behavioral monitor is a detective, defense-in-depth
                # layer on top of the decision above, not the authority
                # for it -- unlike the policy engine and audit log, its
                # failure doesn't retroactively invalidate an already-
                # computed, already-audited decision.
                pass

        return decision

    # -- internals --------------------------------------------------------

    def _evaluate(self, request: ActionRequest) -> PolicyDecision:
        # -1. Type sanitation. request.paths/cwd/command are typed as str,
        # but nothing upstream of this point actually enforces that -- a
        # malformed tool call (a model returning null, a number, or a list
        # for a path-shaped argument, found by fuzzing) can put a non-string
        # value into any of these before build_request's default `or ""`
        # ever runs (e.g. args.get("path", "") returns None, not "", when
        # the key IS present with value None). Every downstream check in
        # this method assumes strings; coercing here once means every one
        # of them can stay simple instead of each needing its own guard.
        request.paths = [p for p in request.paths if isinstance(p, str) and p]
        if not isinstance(request.cwd, str):
            request.cwd = None
        if not isinstance(request.command, str):
            request.command = None

        # -0.5. LOCKDOWN: the most absolute gate in this method, checked
        # before even the per-tool behavioral lockout. In LOCKDOWN, only a
        # small hardcoded set of pure machine-diagnostic reads are allowed
        # -- not "everything READ-category", not anything filesystem- or
        # project-touching. Nothing about how the request is phrased can
        # change this; the only way out is LockdownManager.exit_lockdown(),
        # which itself requires an explicit human confirmation flag.
        if self.lockdown_manager is not None and self.lockdown_manager.is_locked_down():
            if not self.lockdown_manager.is_tool_allowed(request.tool_name):
                return _deny(
                    "JARVIS is in LOCKDOWN mode after suspicious activity was detected. "
                    "Only read-only diagnostics are available. Open the Security Center to review "
                    "what triggered this and exit lockdown explicitly if you want to resume normal use."
                )

        # 0. Behavioral lockout: independent of what this specific request
        # would otherwise resolve to. Checked first and fails closed --
        # a tool under lockout refuses everything, including what would
        # normally be a plain READ, until the cooldown expires or a human
        # clears it from the Security Center.
        if self.security_monitor is not None:
            lockout_reason = self.security_monitor.check_lockout(request)
            if lockout_reason:
                return _deny(lockout_reason)

        # 0b. Kill-switch Level 3: terminal disabled. Independent of the
        # policy category a command would otherwise get -- while disabled,
        # execute_command refuses everything, including a plain "git status".
        if self.kill_switch is not None and self.kill_switch.is_terminal_disabled() and request.tool_name == "execute_command":
            return _deny("Terminal execution is currently disabled (kill-switch Level 3). "
                         "Re-enable it from the Security Center.")

        # 1. Absolute deny list: tool name.
        reason = deny_list.denied_tool(request.tool_name)
        if reason:
            return _deny(reason)

        # 1b. Self-protection: never allow writes into the security/config/audit
        # layers, however the request is phrased.
        self_reason = self._check_self_protection(request)
        if self_reason:
            return _deny(self_reason)

        # 1c. Absolute deny list: paths.
        for path in request.paths:
            reason = deny_list.denied_path(path)
            if reason:
                return _deny(reason)
            reason = deny_list.denied_system_root(path, self.settings.system_deny_roots)
            if reason:
                return _deny(reason)

        # 1d. Absolute deny list: command patterns (independent of category).
        if request.command:
            reason = deny_list.denied_command(request.command)
            if reason:
                return _deny(reason)
            for path in [request.cwd] if request.cwd else []:
                reason = deny_list.denied_path(path) or deny_list.denied_system_root(path, self.settings.system_deny_roots)
                if reason:
                    return _deny(reason)

        # 2. Category resolution.
        category, risk, reasons = self._resolve_category(request)

        if category == PermissionLevel.DENY:
            return PolicyDecision(Decision.DENY, category, risk, reasons)

        if category in (PermissionLevel.READ, PermissionLevel.SAFE):
            return PolicyDecision(Decision.ALLOW, category, risk, reasons)

        if category == PermissionLevel.MODIFY:
            if request.grant_key and self.grant_store and self.grant_store.has_grant(request.grant_key):
                return PolicyDecision(Decision.ALLOW, category, risk, reasons + ["Covered by existing grant."])
            return PolicyDecision(Decision.CONFIRM, category, risk, reasons)

        # DESTRUCTIVE: spec is explicit -- always requires fresh explicit
        # confirmation. No grant, session-wide or otherwise, can bypass this.
        return PolicyDecision(Decision.CONFIRM, PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH, reasons)

    def _check_self_protection(self, request: ActionRequest) -> str | None:
        candidates = list(request.paths)
        if request.cwd:
            candidates.append(request.cwd)
        for raw in candidates:
            # request.paths/cwd are typed as strings, but a malformed tool
            # call (a model returning null/a number/a list for a path
            # argument -- found by fuzzing) can put a non-string value here
            # before this ever reaches a type-checked boundary. Treat
            # anything that isn't a string as simply not matching, rather
            # than letting `in` raise on a non-iterable/wrong-type operand.
            if not isinstance(raw, str) or not raw:
                continue
            normalized = str(Path(raw))
            for marker in _SELF_PROTECTED_SUBSTRINGS:
                if marker in normalized or marker in raw:
                    return "Action would touch JARVIS's own security/config/audit files; self-modification is never allowed."
        if request.tool_name in {"write_file", "delete_file", "modify_file"} and request.args.get("target") == "self":
            return "Self-targeting write/delete actions are never allowed."
        return None

    def _resolve_category(self, request: ActionRequest) -> tuple[PermissionLevel, RiskLevel, list[str]]:
        spec = self.tool_registry.get(request.tool_name)

        if spec is not None and spec.is_command_tool and request.command:
            cls = classify_command(request.command, request.cwd)
            # Set on the request itself so the approval card (built from
            # this same ActionRequest) can show it -- the command classifier
            # is the one place that actually reasons about what the command
            # does, so this is where reversibility gets decided too.
            request.reversibility = cls.reversibility
            if cls.denied:
                return PermissionLevel.DENY, cls.risk, cls.reasons
            return cls.category, cls.risk, cls.reasons

        if spec is None:
            # Unknown tool: fail fully closed. There is no implementation
            # behind this name to run even if a human approved it, so this
            # is a DENY, not a CONFIRM -- matching "I don't currently have
            # permission to do that" rather than offering an approval card
            # for a capability that doesn't exist.
            return PermissionLevel.DENY, RiskLevel.CRITICAL, ["Tool is not in the registry."]

        risk_by_category = {
            PermissionLevel.READ: RiskLevel.LOW,
            PermissionLevel.SAFE: RiskLevel.LOW,
            PermissionLevel.MODIFY: RiskLevel.MEDIUM,
            PermissionLevel.DESTRUCTIVE: RiskLevel.HIGH,
            PermissionLevel.DENY: RiskLevel.CRITICAL,
        }
        reversibility_by_category = {
            PermissionLevel.READ: Reversibility.REVERSIBLE,
            PermissionLevel.SAFE: Reversibility.REVERSIBLE,
            PermissionLevel.MODIFY: Reversibility.REVERSIBLE,
            PermissionLevel.DESTRUCTIVE: Reversibility.IRREVERSIBLE,
            PermissionLevel.DENY: Reversibility.UNKNOWN,
        }
        request.reversibility = reversibility_by_category[spec.base_category]
        return spec.base_category, risk_by_category[spec.base_category], [f"Tool '{spec.name}' base category is {spec.base_category.value}."]


def _deny(reason: str) -> PolicyDecision:
    return PolicyDecision(Decision.DENY, PermissionLevel.DENY, RiskLevel.CRITICAL, [reason], absolute=True)
