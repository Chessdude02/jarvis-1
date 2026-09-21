"""Behavioral anomaly detection, independent of whatever the LLM claims it's
doing. This watches the STREAM of policy decisions -- not individual
requests in isolation -- for patterns that look like probing or an attack
in progress: repeated denials, repeated attempts at the same blocked tool,
or a burst of gated actions arriving faster than a human could plausibly be
approving them.

This is not a replacement for the policy engine's per-request checks; it's
a second, independent layer that reacts to a PATTERN across requests. A
single denied request is normal (the user asked for something JARVIS can't
do); three denials in ten seconds, or five attempts at the same absolutely-
denied tool, is a signal worth surfacing and briefly escalating on.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from jarvis.security.permissions import ActionRequest, Decision, PolicyDecision


@dataclass
class SecurityAlert:
    ts: float
    kind: str
    detail: str
    locked_out_key: str | None = None


class SecurityMonitor:
    def __init__(
        self,
        audit_sink=None,
        window_seconds: float = 60.0,
        denial_threshold: int = 3,
        blocked_tool_threshold: int = 3,
        rapid_action_threshold: int = 6,
        rapid_action_window_seconds: float = 10.0,
        lockout_seconds: float = 120.0,
        lockdown_manager=None,
    ) -> None:
        self.audit_sink = audit_sink
        self.lockdown_manager = lockdown_manager
        self.window_seconds = window_seconds
        self.denial_threshold = denial_threshold
        self.blocked_tool_threshold = blocked_tool_threshold
        self.rapid_action_threshold = rapid_action_threshold
        self.rapid_action_window_seconds = rapid_action_window_seconds
        self.lockout_seconds = lockout_seconds

        self._lock = threading.Lock()
        self._denials: deque[float] = deque()
        self._denials_by_tool: dict[str, deque[float]] = {}
        self._gated_actions: deque[float] = deque()
        self._lockouts: dict[str, float] = {}  # tool_name -> unlocks_at epoch
        self._alerts: deque[SecurityAlert] = deque(maxlen=200)

    # -- read path: consulted BEFORE a decision is made --------------------

    def check_lockout(self, request: ActionRequest) -> str | None:
        with self._lock:
            unlocks_at = self._lockouts.get(request.tool_name)
            if unlocks_at is None:
                return None
            if time.monotonic() >= unlocks_at:
                del self._lockouts[request.tool_name]
                return None
            remaining = round(unlocks_at - time.monotonic())
            return (f"'{request.tool_name}' is temporarily locked out after repeated denied/suspicious "
                    f"attempts ({remaining}s remaining). This is independent of the LLM and cannot be "
                    f"talked past -- wait for the lockout to expire or use the Security Center to clear it.")

    def clear_lockout(self, tool_name: str | None = None) -> int:
        """Manual override, called from the Security Center UI. tool_name=None
        clears every active lockout."""
        with self._lock:
            if tool_name is None:
                count = len(self._lockouts)
                self._lockouts.clear()
                return count
            return 1 if self._lockouts.pop(tool_name, None) is not None else 0

    # -- write path: called AFTER a decision is made ------------------------

    def observe(self, request: ActionRequest, decision: PolicyDecision) -> SecurityAlert | None:
        now = time.monotonic()
        alert: SecurityAlert | None = None
        with self._lock:
            self._prune(now)

            if decision.decision == Decision.CONFIRM:
                self._gated_actions.append(now)
                if len(self._gated_actions) >= self.rapid_action_threshold:
                    span = now - self._gated_actions[0]
                    if span <= self.rapid_action_window_seconds:
                        alert = SecurityAlert(now, "rapid_action_chaining",
                                               f"{len(self._gated_actions)} gated actions requested within "
                                               f"{span:.1f}s -- faster than a human is likely approving them.")

            if decision.decision == Decision.DENY:
                self._denials.append(now)
                per_tool = self._denials_by_tool.setdefault(request.tool_name, deque())
                per_tool.append(now)

                if len(self._denials) >= self.denial_threshold:
                    alert = alert or SecurityAlert(now, "repeated_denials",
                                                    f"{len(self._denials)} denied actions within {self.window_seconds:.0f}s "
                                                    f"(most recent: {request.tool_name}).")

                if len(per_tool) >= self.blocked_tool_threshold:
                    lockout_until = now + self.lockout_seconds
                    self._lockouts[request.tool_name] = lockout_until
                    alert = SecurityAlert(
                        now, "repeated_blocked_tool_attempts",
                        f"'{request.tool_name}' was denied {len(per_tool)} times within {self.window_seconds:.0f}s "
                        f"-- looks like repeated probing or a jailbreak attempt rather than an accident. "
                        f"Locking '{request.tool_name}' out for {self.lockout_seconds:.0f}s.",
                        locked_out_key=request.tool_name,
                    )

            if alert:
                self._alerts.append(alert)

        if alert and self.audit_sink:
            self.audit_sink.record(
                event_type="security_alert", kind=alert.kind, detail=alert.detail,
                tool=request.tool_name, locked_out=alert.locked_out_key,
            )
        if alert and self.lockdown_manager is not None:
            # Any alert here already crossed a real threshold (not noise);
            # feed it into the global lockdown state machine, which
            # auto-escalates to full LOCKDOWN if this keeps happening.
            self.lockdown_manager.mark_suspicious(f"{alert.kind}: {alert.detail}")
        return alert

    def _prune(self, now: float) -> None:
        while self._denials and now - self._denials[0] > self.window_seconds:
            self._denials.popleft()
        for dq in self._denials_by_tool.values():
            while dq and now - dq[0] > self.window_seconds:
                dq.popleft()
        while self._gated_actions and now - self._gated_actions[0] > self.rapid_action_window_seconds:
            self._gated_actions.popleft()

    # -- inspection, for the Security Center -------------------------------

    def recent_alerts(self, limit: int = 20) -> list[SecurityAlert]:
        with self._lock:
            return list(self._alerts)[-limit:]

    def active_lockouts(self) -> dict[str, float]:
        with self._lock:
            now = time.monotonic()
            return {tool: round(until - now) for tool, until in self._lockouts.items() if until > now}
