"""The kill-switch hierarchy. Every level here is a plain method call the UI
(a hotkey handler, a Security Center button) invokes directly -- none of
them go through the orchestrator, the LLM, or a tool call. That's the whole
point: these must keep working even if the LLM is stuck, hallucinating, or
the orchestrator loop has hung.

    LEVEL 1  cancel_current_action   -- stop just the most recent execution
    LEVEL 2  stop_all_actions        -- kill everything, cancel the queue
    LEVEL 3  disable_terminal        -- refuse every execute_command until re-enabled
    LEVEL 4  disable_network         -- force the (currently unbuilt, opt-in)
                                        online-information feature off
    LEVEL 5  request_exit            -- audit the exit, caller then quits the app

This module has no PySide6 import and no orchestrator import -- it only
touches Sandbox (to actually kill processes) and an optional audit sink.
That keeps it usable from any thread, including directly from a low-level
keyboard hook callback.
"""
from __future__ import annotations

import threading


class KillSwitch:
    def __init__(self, sandbox, audit_sink=None, security_monitor=None) -> None:
        self.sandbox = sandbox
        self.audit_sink = audit_sink
        self.security_monitor = security_monitor
        self._lock = threading.Lock()
        self.terminal_disabled = False
        self.network_disabled = False
        self._orchestrator_stop_callbacks: list = []

    def register_orchestrator_stop(self, callback) -> None:
        """Orchestrator.emergency_stop (sets its stop_event) gets called as
        part of Level 2 too, so a turn already in flight actually stops
        reasoning about further steps, not just loses its subprocess."""
        self._orchestrator_stop_callbacks.append(callback)

    def _audit(self, event_type: str, **data) -> None:
        if self.audit_sink is not None:
            self.audit_sink.record(event_type=event_type, **data)

    # -- LEVEL 1 -------------------------------------------------------------

    def cancel_current_action(self) -> bool:
        execution_id = self.sandbox.most_recent_execution_id() if self.sandbox else None
        if execution_id is None:
            self._audit("kill_switch_level1_cancel_current", found_action=False)
            return False
        terminated = self.sandbox.terminate(execution_id)
        self._audit("kill_switch_level1_cancel_current", found_action=True, execution_id=execution_id, terminated=terminated)
        return terminated

    # -- LEVEL 2 -------------------------------------------------------------

    def stop_all_actions(self) -> int:
        killed = self.sandbox.emergency_stop_all() if self.sandbox else 0
        for callback in self._orchestrator_stop_callbacks:
            try:
                callback()
            except Exception:
                pass
        self._audit("kill_switch_level2_stop_all", processes_killed=killed)
        return killed

    # -- LEVEL 3 -------------------------------------------------------------

    def disable_terminal(self) -> None:
        with self._lock:
            self.terminal_disabled = True
        self._audit("kill_switch_level3_disable_terminal")

    def enable_terminal(self) -> None:
        with self._lock:
            self.terminal_disabled = False
        self._audit("kill_switch_terminal_re_enabled")

    def is_terminal_disabled(self) -> bool:
        with self._lock:
            return self.terminal_disabled

    # -- LEVEL 4 -------------------------------------------------------------

    def disable_network(self) -> None:
        with self._lock:
            self.network_disabled = True
        self._audit("kill_switch_level4_disable_network")

    def enable_network(self) -> None:
        with self._lock:
            self.network_disabled = False
        self._audit("kill_switch_network_re_enabled")

    def is_network_disabled(self) -> bool:
        with self._lock:
            return self.network_disabled

    # -- LEVEL 5 -------------------------------------------------------------

    def request_exit(self) -> None:
        """Only audits the exit; the caller (UI) still has to actually quit
        the application. Kept separate from QApplication on purpose --
        this module must stay importable and testable without PySide6."""
        self._audit("kill_switch_level5_exit_requested")

    # -- full status, for the Security Center --------------------------------

    def status(self) -> dict:
        with self._lock:
            return {
                "terminal_disabled": self.terminal_disabled,
                "network_disabled": self.network_disabled,
                "active_processes": self.sandbox.active_count if self.sandbox else 0,
            }
