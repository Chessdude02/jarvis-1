"""Compromised-JARVIS mode (spec: NORMAL -> SUSPICIOUS -> LOCKDOWN).

This is a single global gate the policy engine checks before anything
else -- more absolute than a per-tool SecurityMonitor lockout (which only
blocks the specific tool that triggered it). LOCKDOWN blocks essentially
everything except a small, hardcoded set of read-only diagnostic tools,
and the only way out is an explicit, human-initiated exit call. Nothing
in this module is reachable from a tool the LLM can call -- entering or
leaving lockdown is always a direct method call from SecurityMonitor
(automatic escalation) or the Security Center UI (manual).
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum

# The only tools left reachable during LOCKDOWN: pure machine-diagnostic
# reads with no filesystem/project/network(beyond Ollama) surface at all.
# Deliberately narrower than "everything READ-category" -- e.g.
# search_projects and read_text_file are READ/SAFE but touch the
# filesystem, so they're excluded here even though they're always-allowed
# under normal operation.
LOCKDOWN_ALLOWED_TOOLS = frozenset({
    "get_system_info", "get_cpu_usage", "get_memory_usage", "get_disk_usage",
    "get_gpu_info", "get_battery_status", "get_network_status",
    "get_running_processes", "get_environment_info",
})


class SecurityState(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    LOCKDOWN = "LOCKDOWN"


@dataclass
class LockdownEvent:
    ts: float
    state: SecurityState
    reason: str


class LockdownManager:
    def __init__(
        self,
        audit_sink=None,
        suspicious_window_seconds: float = 300.0,
        suspicious_threshold_for_auto_lockdown: int = 2,
    ) -> None:
        self.audit_sink = audit_sink
        self.suspicious_window_seconds = suspicious_window_seconds
        self.suspicious_threshold = suspicious_threshold_for_auto_lockdown

        self._lock = threading.Lock()
        self._state = SecurityState.NORMAL
        self._reason = ""
        self._entered_at = time.time()
        self._suspicious_marks: deque[float] = deque()
        self._history: deque[LockdownEvent] = deque(maxlen=100)

    @property
    def state(self) -> SecurityState:
        with self._lock:
            return self._state

    def is_locked_down(self) -> bool:
        return self.state == SecurityState.LOCKDOWN

    def is_normal(self) -> bool:
        return self.state == SecurityState.NORMAL

    def _audit(self, event_type: str, **data) -> None:
        if self.audit_sink is not None:
            self.audit_sink.record(event_type=event_type, **data)

    def mark_suspicious(self, reason: str) -> SecurityState:
        """Called by SecurityMonitor when it observes a pattern serious
        enough to matter beyond a single tool's lockout, but not
        necessarily severe enough for immediate lockdown on its own.
        Repeated marks within the rolling window auto-escalate to LOCKDOWN.
        """
        now = time.time()
        with self._lock:
            if self._state == SecurityState.LOCKDOWN:
                return self._state  # already maximally restricted
            while self._suspicious_marks and now - self._suspicious_marks[0] > self.suspicious_window_seconds:
                self._suspicious_marks.popleft()
            self._suspicious_marks.append(now)
            escalate = len(self._suspicious_marks) >= self.suspicious_threshold
            self._state = SecurityState.SUSPICIOUS
            self._reason = reason
            self._history.append(LockdownEvent(now, SecurityState.SUSPICIOUS, reason))
        self._audit("security_state_suspicious", reason=reason)
        if escalate:
            return self.enter_lockdown(
                f"Auto-escalated: {len(self._suspicious_marks)} suspicious events within "
                f"{self.suspicious_window_seconds:.0f}s (latest: {reason})"
            )
        return SecurityState.SUSPICIOUS

    def enter_lockdown(self, reason: str) -> SecurityState:
        now = time.time()
        with self._lock:
            self._state = SecurityState.LOCKDOWN
            self._reason = reason
            self._entered_at = now
            self._history.append(LockdownEvent(now, SecurityState.LOCKDOWN, reason))
        self._audit("security_lockdown_entered", reason=reason)
        return SecurityState.LOCKDOWN

    def exit_lockdown(self, user_confirmed: bool) -> bool:
        """The ONLY way out. Requires an explicit affirmative flag from the
        caller (the Security Center button sets this to True) -- there is
        no code path that clears lockdown as a side effect of anything
        else, including time passing or the LLM saying anything at all.
        """
        if not user_confirmed:
            return False
        now = time.time()
        with self._lock:
            if self._state != SecurityState.LOCKDOWN:
                return False
            self._state = SecurityState.NORMAL
            self._reason = ""
            self._suspicious_marks.clear()
            self._history.append(LockdownEvent(now, SecurityState.NORMAL, "user-initiated exit"))
        self._audit("security_lockdown_exited", by="user")
        return True

    def is_tool_allowed(self, tool_name: str) -> bool:
        if self.state != SecurityState.LOCKDOWN:
            return True
        return tool_name in LOCKDOWN_ALLOWED_TOOLS

    def status(self) -> dict:
        with self._lock:
            return {
                "state": self._state.value,
                "reason": self._reason,
                "since": self._entered_at,
                "suspicious_marks_in_window": len(self._suspicious_marks),
                "history": [{"ts": e.ts, "state": e.state.value, "reason": e.reason} for e in list(self._history)[-10:]],
            }
