"""The Security Center: visibility into everything the security layer is
doing, plus the actionable controls the spec calls for (revoke session
permissions, stop all actions, disable network/terminal, reset permissions,
view audit log). This window is deliberately outside the LLM's control --
it is never registered as a tool, has no ActionRequest path into it, and
every button here calls straight into KillSwitch/Memory/AuditLog the same
way a hotkey handler would, never through the orchestrator.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton, QScrollArea, QTextEdit, QVBoxLayout, QWidget,
)

_STYLE = """
QWidget { background-color: #12151c; color: #e6ecf5; font-family: Consolas, monospace; font-size: 12px; }
QLabel#heading { font-size: 15px; font-weight: bold; color: #7fd0ff; }
QLabel#section { font-weight: bold; color: #ffb347; margin-top: 8px; }
QPushButton { border: none; border-radius: 6px; padding: 6px 10px; color: white; background-color: #2a3040; }
QPushButton:hover { background-color: #38405a; }
QPushButton#danger { background-color: #b03030; }
QPushButton#danger:hover { background-color: #c94040; }
QTextEdit { background-color: #0c0f14; border: 1px solid #2a3040; border-radius: 6px; padding: 6px; }
"""

_LOCKDOWN_COLORS = {"NORMAL": "#7fd18f", "SUSPICIOUS": "#ffd27f", "LOCKDOWN": "#ff6b6b"}


class SecurityCenterWindow(QDialog):
    def __init__(self, app_ctx, parent=None) -> None:
        """app_ctx is the JarvisApp instance -- this window reads settings,
        sandbox, memory, security_monitor, kill_switch, audit_log, registry
        directly off it and calls their real methods. No LLM/orchestrator
        involvement anywhere in this file.
        """
        super().__init__(parent)
        self.ctx = app_ctx
        self.setWindowTitle("JARVIS Security Center")
        self.setStyleSheet(_STYLE)
        self.setMinimumSize(460, 620)

        outer = QVBoxLayout(self)
        heading = QLabel("SECURITY CENTER", self)
        heading.setObjectName("heading")
        outer.addWidget(heading)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        body = QWidget()
        self.layout_ = QVBoxLayout(body)
        scroll.setWidget(body)
        outer.addWidget(scroll)

        self.lockdown_label = self._section("LOCKDOWN STATUS")
        self.status_label = self._section("STATUS")
        self.permissions_label = self._section("ACTIVE PERMISSIONS")
        self.actions_label = self._section("RUNNING / RECENT ACTIONS")
        self.blocked_label = self._section("BLOCKED ACTIONS / ALERTS")
        self.rate_limit_label = self._section("RATE LIMITS")
        self.dirs_label = self._section("ALLOWED DIRECTORIES")
        self.network_label = self._section("NETWORK")
        self.limits_label = self._section("RESOURCE LIMITS")

        controls_heading = QLabel("CONTROLS", body)
        controls_heading.setObjectName("section")
        self.layout_.addWidget(controls_heading)

        row1 = QHBoxLayout()
        self.btn_revoke_session = QPushButton("Revoke Session Permissions", body)
        self.btn_revoke_session.clicked.connect(self._revoke_session_permissions)
        self.btn_reset_permissions = QPushButton("Reset All Permissions", body)
        self.btn_reset_permissions.setObjectName("danger")
        self.btn_reset_permissions.clicked.connect(self._reset_all_permissions)
        row1.addWidget(self.btn_revoke_session)
        row1.addWidget(self.btn_reset_permissions)
        self.layout_.addLayout(row1)

        row2 = QHBoxLayout()
        self.btn_cancel_current = QPushButton("Cancel Current Action (L1)", body)
        self.btn_cancel_current.clicked.connect(self._cancel_current_action)
        self.btn_stop_all = QPushButton("Stop All Actions (L2)", body)
        self.btn_stop_all.setObjectName("danger")
        self.btn_stop_all.clicked.connect(self._stop_all_actions)
        row2.addWidget(self.btn_cancel_current)
        row2.addWidget(self.btn_stop_all)
        self.layout_.addLayout(row2)

        row3 = QHBoxLayout()
        self.btn_toggle_terminal = QPushButton("Disable Terminal (L3)", body)
        self.btn_toggle_terminal.clicked.connect(self._toggle_terminal)
        self.btn_toggle_network = QPushButton("Disable Network (L4)", body)
        self.btn_toggle_network.clicked.connect(self._toggle_network)
        row3.addWidget(self.btn_toggle_terminal)
        row3.addWidget(self.btn_toggle_network)
        self.layout_.addLayout(row3)

        row4 = QHBoxLayout()
        self.btn_clear_lockouts = QPushButton("Clear Behavioral Lockouts", body)
        self.btn_clear_lockouts.clicked.connect(self._clear_lockouts)
        self.btn_reset_rate_limits = QPushButton("Reset Rate Limits", body)
        self.btn_reset_rate_limits.clicked.connect(self._reset_rate_limits)
        row4.addWidget(self.btn_clear_lockouts)
        row4.addWidget(self.btn_reset_rate_limits)
        self.layout_.addLayout(row4)

        row5 = QHBoxLayout()
        self.btn_toggle_lockdown = QPushButton("Enter Lockdown", body)
        self.btn_toggle_lockdown.setObjectName("danger")
        self.btn_toggle_lockdown.clicked.connect(self._toggle_lockdown)
        self.btn_view_audit = QPushButton("View Audit Log", body)
        self.btn_view_audit.clicked.connect(self._view_audit_log)
        row5.addWidget(self.btn_toggle_lockdown)
        row5.addWidget(self.btn_view_audit)
        self.layout_.addLayout(row5)

        self.layout_.addStretch()

        self.audit_view: AuditLogViewer | None = None
        self.refresh()

    def _section(self, title: str) -> QLabel:
        heading = QLabel(title, self)
        heading.setObjectName("section")
        self.layout_.addWidget(heading)
        content = QLabel("", self)
        content.setTextFormat(Qt.RichText)
        content.setWordWrap(True)
        self.layout_.addWidget(content)
        return content

    # -- data refresh --------------------------------------------------------

    def refresh(self) -> None:
        ctx = self.ctx
        ks_status = ctx.kill_switch.status()
        terminal_state = '<span style="color:#ff6b6b">DISABLED</span>' if ks_status["terminal_disabled"] else "enabled"

        if ctx.lockdown_manager is not None:
            ld_status = ctx.lockdown_manager.status()
            color = _LOCKDOWN_COLORS.get(ld_status["state"], "#e6ecf5")
            history_lines = "<br>".join(
                f"&nbsp;&nbsp;[{h['state']}] {h['reason'][:80]}" for h in reversed(ld_status["history"][-5:])
            ) or "&nbsp;&nbsp;(no events yet)"
            self.lockdown_label.setText(
                f"State: <span style='color:{color}'><b>{ld_status['state']}</b></span><br>"
                f"Reason: {ld_status['reason'] or '(none)'}<br>"
                f"Recent history:<br>{history_lines}"
            )
            is_locked = ld_status["state"] == "LOCKDOWN"
            self.btn_toggle_lockdown.setText("Exit Lockdown" if is_locked else "Enter Lockdown")
        else:
            self.lockdown_label.setText("Lockdown manager not configured.")

        self.status_label.setText(
            f"LLM: {'Online' if ctx.llm_client.is_available() else 'Offline'}<br>"
            f"Model: {ctx.settings.llm_model}<br>"
            f"Tools enabled: {len(ctx.registry.all())}<br>"
            f"Terminal: {terminal_state}<br>"
            f"Guardrails / audit logging / redaction: active"
        )

        session_grants = ctx.memory.list_session_grants()
        permanent_grants = ctx.memory.list_permanent_grants()
        self.permissions_label.setText(
            f"Session grants (expire on exit): {len(session_grants)}<br>"
            + "<br>".join(f"&nbsp;&nbsp;{g}" for g in session_grants[:10])
            + (f"<br>Permanent grants: {len(permanent_grants)}" if permanent_grants else "<br>Permanent grants: 0")
        )

        recent = ctx.memory.recent_actions(limit=8)
        self.actions_label.setText(
            f"Currently running: {ks_status['active_processes']}<br>"
            "Recent:<br>" + ("<br>".join(f"&nbsp;&nbsp;[{a['status']}] {a['summary'][:60]}" for a in reversed(recent)) or "&nbsp;&nbsp;(none yet)")
        )

        alerts = ctx.security_monitor.recent_alerts(limit=5) if ctx.security_monitor else []
        lockouts = ctx.security_monitor.active_lockouts() if ctx.security_monitor else {}
        self.blocked_label.setText(
            f"Active lockouts: {len(lockouts)}<br>"
            + "".join(f"&nbsp;&nbsp;{tool}: {secs}s remaining<br>" for tool, secs in lockouts.items())
            + "Recent alerts:<br>"
            + ("<br>".join(f"&nbsp;&nbsp;[{a.kind}] {a.detail[:70]}" for a in reversed(alerts)) or "&nbsp;&nbsp;(none)")
        )

        if ctx.rate_limiter is not None:
            rl_status = ctx.rate_limiter.status()
            self.rate_limit_label.setText(
                "<br>".join(
                    f"&nbsp;&nbsp;{cat}: {s['recent_events']}/{s['limit']} per {s['window_seconds']:.0f}s"
                    + (f" <span style='color:#ff6b6b'>({s['violations']} violation(s))</span>" if s["violations"] else "")
                    for cat, s in rl_status.items()
                ) or "(no categories configured)"
            )
        else:
            self.rate_limit_label.setText("Rate limiter not configured.")

        self.dirs_label.setText("<br>".join(ctx.settings.indexed_roots) or "(none configured)")

        network_state = '<span style="color:#ff6b6b">DISABLED</span>' if ks_status["network_disabled"] else "not engaged"
        self.network_label.setText(
            f"Online-information feature: {'enabled' if ctx.settings.online_features_enabled else 'disabled (default)'}<br>"
            f"Kill-switch network override: {network_state}"
        )

        limits = ctx.settings.limits
        self.limits_label.setText(
            f"Max command runtime: {limits.max_command_execution_seconds}s &nbsp; "
            f"Max concurrent commands: {limits.max_subprocess_count}<br>"
            f"Max commands/request: {limits.max_commands_per_request} &nbsp; "
            f"Max output: {limits.max_output_bytes} bytes<br>"
            f"Max recursion depth: {limits.max_recursive_depth} &nbsp; "
            f"Max files scanned: {limits.max_files_scanned_per_search}"
        )

        self.btn_toggle_terminal.setText("Enable Terminal (L3)" if ks_status["terminal_disabled"] else "Disable Terminal (L3)")
        self.btn_toggle_network.setText("Enable Network (L4)" if ks_status["network_disabled"] else "Disable Network (L4)")

    # -- controls ------------------------------------------------------------

    def _revoke_session_permissions(self) -> None:
        self.ctx.memory.clear_session_grants()
        self.refresh()

    def _reset_all_permissions(self) -> None:
        self.ctx.memory.delete_all("grants")
        self.refresh()

    def _cancel_current_action(self) -> None:
        self.ctx.kill_switch.cancel_current_action()
        self.refresh()

    def _stop_all_actions(self) -> None:
        self.ctx.kill_switch.stop_all_actions()
        self.refresh()

    def _toggle_terminal(self) -> None:
        if self.ctx.kill_switch.is_terminal_disabled():
            self.ctx.kill_switch.enable_terminal()
        else:
            self.ctx.kill_switch.disable_terminal()
        self.refresh()

    def _toggle_network(self) -> None:
        if self.ctx.kill_switch.is_network_disabled():
            self.ctx.kill_switch.enable_network()
        else:
            self.ctx.kill_switch.disable_network()
        self.refresh()

    def _clear_lockouts(self) -> None:
        if self.ctx.security_monitor:
            self.ctx.security_monitor.clear_lockout()
        self.refresh()

    def _reset_rate_limits(self) -> None:
        if self.ctx.rate_limiter:
            self.ctx.rate_limiter.reset()
        self.refresh()

    def _toggle_lockdown(self) -> None:
        ld = self.ctx.lockdown_manager
        if ld is None:
            return
        if ld.is_locked_down():
            reply = QMessageBox.question(
                self, "Exit Lockdown",
                "JARVIS is in LOCKDOWN mode. Exiting resumes normal operation immediately.\n\n"
                "Only do this if you understand what triggered lockdown. Continue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                ld.exit_lockdown(user_confirmed=True)
        else:
            reply = QMessageBox.question(
                self, "Enter Lockdown",
                "This immediately restricts JARVIS to read-only diagnostics only -- "
                "no file access, no terminal, no automation -- until you explicitly exit. Continue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                ld.enter_lockdown("Manually triggered from the Security Center")
        self.refresh()

    def _view_audit_log(self) -> None:
        self.audit_view = AuditLogViewer(self.ctx.audit_log, self)
        self.audit_view.show()


class AuditLogViewer(QDialog):
    def __init__(self, audit_log, parent=None) -> None:
        super().__init__(parent)
        self.audit_log = audit_log
        self.setWindowTitle("JARVIS Audit Log")
        self.setStyleSheet(_STYLE)
        self.setMinimumSize(560, 420)

        layout = QVBoxLayout(self)
        verify_row = QHBoxLayout()
        self.verify_label = QLabel("", self)
        refresh_btn = QPushButton("Refresh", self)
        refresh_btn.clicked.connect(self.refresh)
        verify_row.addWidget(self.verify_label)
        verify_row.addStretch()
        verify_row.addWidget(refresh_btn)
        layout.addLayout(verify_row)

        self.text = QTextEdit(self)
        self.text.setReadOnly(True)
        layout.addWidget(self.text)

        self.refresh()

    def refresh(self) -> None:
        ok, bad_id = self.audit_log.verify_chain()
        color = "#7fd18f" if ok else "#ff6b6b"
        status_text = "VERIFIED" if ok else f"TAMPERED at id={bad_id}"
        self.verify_label.setText(f"Chain integrity: <span style='color:{color}'>{status_text}</span>")
        events = list(self.audit_log.iter_events())[-200:]
        lines = []
        for e in reversed(events):
            lines.append(f"{e.ts}  [{e.event_type}]  {e.data}")
        self.text.setPlainText("\n".join(lines) or "(no audit events yet)")
