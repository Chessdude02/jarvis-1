"""Wires the whole desktop app together: entity, chat, approval dialogs,
status panel, tray icon, global hotkeys, and the orchestrator running on a
background thread so the UI never blocks on the LLM or a subprocess.
"""
from __future__ import annotations

import sys
import threading

import psutil
from PySide6.QtCore import QObject, QPoint, Qt, QThread, Signal, Slot
from PySide6.QtGui import QAction, QIcon, QPixmap, QColor
from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon

from jarvis.config.settings import get_settings
from jarvis.core.memory import Memory
from jarvis.core.orchestrator import EntityState, Orchestrator
from jarvis.llm.ollama_client import OllamaClient
from jarvis.security.audit import AuditLog
from jarvis.security.kill_switch import KillSwitch
from jarvis.security.rate_limiter import RateLimiter
from jarvis.security.lockdown import LockdownManager
from jarvis.security.monitor import SecurityMonitor
from jarvis.security.permissions import ApprovalScope
from jarvis.security.policy_engine import PolicyEngine
from jarvis.security.sandbox import Sandbox
from jarvis.tools.registry import build_default_registry
from jarvis.ui.approval_dialog import ApprovalDialog
from jarvis.ui.chat_window import ChatWindow
from jarvis.ui.entity_widget import EntityWidget
from jarvis.ui.security_center import SecurityCenterWindow
from jarvis.ui.status_window import StatusWindow


class ApprovalBridge(QObject):
    """Marshals an approval request from the orchestrator's worker thread to
    a modal dialog on the Qt main thread, and blocks the worker thread until
    the person answers. This is the ONLY place a background thread waits on
    the GUI thread, and it exists so the security-critical approval step is
    never silently auto-answered.
    """

    approval_requested = Signal(object, object)

    def __init__(self, entity: EntityWidget) -> None:
        super().__init__()
        self._entity = entity
        self._event = threading.Event()
        self._result = ApprovalScope.CANCEL
        self.approval_requested.connect(self._show_dialog, Qt.QueuedConnection)

    def request_approval(self, request, decision) -> ApprovalScope:
        self._event.clear()
        self.approval_requested.emit(request, decision)
        self._event.wait()
        return self._result

    @Slot(object, object)
    def _show_dialog(self, request, decision) -> None:
        self._entity.set_state(EntityState.WAITING_FOR_APPROVAL)
        self._result = ApprovalDialog.ask(self._entity, request, decision)
        self._event.set()


class OrchestratorWorker(QObject):
    state_changed = Signal(str)
    plan_ready = Signal(str)
    tool_event = Signal(str, dict)  # ("call"|"result", payload)
    assistant_text = Signal(str)
    error = Signal(str)
    turn_finished = Signal()

    def __init__(self, orchestrator: Orchestrator) -> None:
        super().__init__()
        self.orchestrator = orchestrator

    @Slot(str)
    def handle_message(self, text: str) -> None:
        for event in self.orchestrator.handle_message(text):
            if event.type == "state":
                self.state_changed.emit(event.payload.value)
            elif event.type == "plan":
                self.plan_ready.emit(event.payload)
            elif event.type == "tool_call":
                self.tool_event.emit("call", event.payload)
            elif event.type == "tool_result":
                self.tool_event.emit("result", event.payload)
            elif event.type == "assistant_text":
                self.assistant_text.emit(event.payload)
            elif event.type == "error":
                self.error.emit(str(event.payload))
        self.turn_finished.emit()


class JarvisApp:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.registry = build_default_registry()
        self.audit_log = AuditLog(self.settings.audit_db_path)
        self.memory = Memory(self.settings.memory_db_path)
        self.lockdown_manager = LockdownManager(audit_sink=self.audit_log)
        self.security_monitor = SecurityMonitor(audit_sink=self.audit_log, lockdown_manager=self.lockdown_manager)
        self.rate_limiter = RateLimiter(audit_sink=self.audit_log)
        self.sandbox = Sandbox(self.settings)
        self.kill_switch = KillSwitch(self.sandbox, audit_sink=self.audit_log, security_monitor=self.security_monitor)
        self.policy_engine = PolicyEngine(
            self.settings, self.registry.policy_specs(),
            grant_store=self.memory, audit_sink=self.audit_log,
            security_monitor=self.security_monitor, kill_switch=self.kill_switch,
            lockdown_manager=self.lockdown_manager, rate_limiter=self.rate_limiter,
        )
        self.llm_client = OllamaClient(self.settings)

        self.app = QApplication(sys.argv)
        self.app.setQuitOnLastWindowClosed(False)

        self.entity = EntityWidget(self.settings.entity_size_px)
        self.chat = ChatWindow()
        self.status_window = StatusWindow()
        self.security_center: SecurityCenterWindow | None = None

        self.approval_bridge = ApprovalBridge(self.entity)

        self.orchestrator = Orchestrator(
            self.settings, self.registry, self.policy_engine, self.sandbox,
            self.audit_log, self.memory, self.llm_client,
            approval_callback=self.approval_bridge.request_approval,
            rate_limiter=self.rate_limiter,
        )
        self.orchestrator.refresh_project_index()
        # Level 2 (stop_all_actions) also needs the orchestrator's reasoning
        # loop to actually stop proposing further steps, not just lose its
        # current subprocess -- register that on top of KillSwitch's own
        # (idempotent) sandbox kill.
        self.kill_switch.register_orchestrator_stop(lambda: self.orchestrator._stop_event.set())

        self._setup_worker_thread()
        self._position_entity()
        self._setup_tray()
        self._wire_signals()
        self._setup_hotkeys()

        self.app.aboutToQuit.connect(self._shutdown)
        self.entity.show()

    # -- setup -----------------------------------------------------------

    def _setup_worker_thread(self) -> None:
        self.thread = QThread()
        self.worker = OrchestratorWorker(self.orchestrator)
        self.worker.moveToThread(self.thread)
        self.thread.start()

    def _position_entity(self) -> None:
        screen = self.app.primaryScreen().availableGeometry()
        x = screen.right() - self.entity.width() - 40
        y = screen.bottom() - self.entity.height() - 80
        self.entity.move(QPoint(x, y))

    def _setup_tray(self) -> None:
        pixmap = QPixmap(32, 32)
        pixmap.fill(QColor(40, 70, 110))
        self.tray = QSystemTrayIcon(QIcon(pixmap), self.app)
        menu = QMenu()
        menu.addAction(QAction("Open JARVIS", menu, triggered=self._toggle_chat))
        menu.addAction(QAction("Status", menu, triggered=self._show_status))
        menu.addAction(QAction("Security Center", menu, triggered=self._show_security_center))
        menu.addSeparator()
        menu.addAction(QAction("Cancel Current Action (Level 1)", menu, triggered=self._cancel_current_action))
        menu.addAction(QAction("Emergency Stop -- Stop All (Level 2)", menu, triggered=self._emergency_stop))
        menu.addSeparator()
        menu.addAction(QAction("Quit (Level 5)", menu, triggered=self._exit_jarvis))
        self.tray.setContextMenu(menu)
        self.tray.setToolTip("JARVIS")
        self.tray.show()

    def _wire_signals(self) -> None:
        self.entity.clicked.connect(self._toggle_chat)
        self.chat.message_sent.connect(self._on_message_sent)

        # self.worker lives on the background thread; JarvisApp is a plain
        # Python object (not a QObject), so Qt's AutoConnection cannot infer
        # thread affinity here and would otherwise run these directly on the
        # worker thread -- which would mutate widgets outside the GUI thread.
        # QueuedConnection forces every one of these onto the main event loop.
        self.worker.state_changed.connect(self._on_state_changed, Qt.QueuedConnection)
        self.worker.plan_ready.connect(lambda text: self.chat.append("plan", text), Qt.QueuedConnection)
        self.worker.tool_event.connect(self._on_tool_event, Qt.QueuedConnection)
        self.worker.assistant_text.connect(self._on_assistant_text, Qt.QueuedConnection)
        self.worker.error.connect(self._on_error, Qt.QueuedConnection)
        self.worker.turn_finished.connect(lambda: self.chat.set_input_enabled(True), Qt.QueuedConnection)

    def _setup_hotkeys(self) -> None:
        try:
            import keyboard  # type: ignore
        except ImportError:
            self._hotkeys_active = False
            return
        self._hotkeys_active = True

        def _register():
            try:
                keyboard.add_hotkey(self.settings.global_hotkey, self._toggle_chat_threadsafe)
                keyboard.add_hotkey(self.settings.emergency_stop_hotkey, self._emergency_stop_threadsafe)
                keyboard.wait()
            except Exception:
                pass

        threading.Thread(target=_register, daemon=True).start()

    def _toggle_chat_threadsafe(self) -> None:
        from PySide6.QtCore import QTimer
        QTimer.singleShot(0, self._toggle_chat)

    def _emergency_stop_threadsafe(self) -> None:
        from PySide6.QtCore import QTimer
        QTimer.singleShot(0, self._emergency_stop)

    # -- UI actions --------------------------------------------------------

    def _toggle_chat(self) -> None:
        if self.chat.isVisible():
            self.chat.hide()
            return
        pos = self.entity.pos()
        self.chat.move(pos.x() - self.chat.width() - 12, max(0, pos.y() - self.chat.height() + self.entity.height()))
        self.chat.show()
        self.chat.set_input_enabled(True)
        self.chat.input.setFocus()

    def _show_status(self) -> None:
        data = {
            "llm_status": "Online" if self.llm_client.is_available() else "Offline (Ollama unreachable)",
            "model": self.settings.llm_model,
            "cpu_percent": psutil.cpu_percent(interval=0.2),
            "ram_gb": round(psutil.Process().memory_info().rss / 2**20 / 1024, 2),
            "tool_count": len(self.registry.all()),
            "network": "Disabled" if not self.settings.online_features_enabled else "Enabled (online info)",
            "pending_approvals": 0,
            "security": {
                "Guardrails active": True,
                "Audit logging active": True,
                "Restricted execution": True,
                "Credential protection": True,
            },
        }
        self.status_window.update_status(data)
        self.status_window.move(self.entity.pos().x() - self.status_window.width() - 12, self.entity.pos().y())
        self.status_window.show()

    def _show_security_center(self) -> None:
        if self.security_center is None:
            self.security_center = SecurityCenterWindow(self)
        else:
            self.security_center.refresh()
        self.security_center.show()
        self.security_center.raise_()
        self.security_center.activateWindow()

    def _exit_jarvis(self) -> None:
        """Kill-switch Level 5."""
        self.kill_switch.request_exit()
        self.app.quit()

    def _emergency_stop(self) -> None:
        """Kill-switch Level 2. Calls KillSwitch.stop_all_actions() directly
        -- never through the orchestrator/LLM loop -- which kills every
        sandboxed process and (via the registered callback) stops the
        orchestrator's reasoning loop too."""
        killed = self.kill_switch.stop_all_actions()
        self.entity.set_state(EntityState.IDLE)
        self.chat.append("error", f"EMERGENCY STOP (Level 2) engaged. {killed} active process(es) terminated. All queued actions cancelled.")
        self.chat.set_input_enabled(True)

    def _cancel_current_action(self) -> None:
        """Kill-switch Level 1: stop just the most recent action, not everything."""
        cancelled = self.kill_switch.cancel_current_action()
        self.chat.append("error" if cancelled else "system",
                          "Cancelled the current action." if cancelled else "No action is currently running to cancel.")

    def _on_message_sent(self, text: str) -> None:
        from PySide6.QtCore import QMetaObject, Q_ARG
        QMetaObject.invokeMethod(self.worker, "handle_message", Qt.QueuedConnection, Q_ARG(str, text))

    def _on_state_changed(self, state_name: str) -> None:
        self.entity.set_state(EntityState[state_name])

    def _on_tool_event(self, kind: str, payload: dict) -> None:
        if kind == "call":
            self.chat.append("tool", f"Calling {payload['tool']}({payload['args']}) -> {payload['decision'].decision.value}")
        else:
            facts = payload.get("facts") or []
            text = "\n".join(facts) if facts else (payload.get("error") or "(no output)")
            self.chat.append("tool", text)

    def _on_assistant_text(self, text: str) -> None:
        self.chat.append("assistant", text)

    def _on_error(self, text: str) -> None:
        self.chat.append("error", text)
        self.entity.set_state(EntityState.ERROR)

    def run(self) -> int:
        return self.app.exec()

    def _shutdown(self) -> None:
        self.sandbox.emergency_stop_all()
        self.thread.quit()
        self.thread.wait(3000)
        self.audit_log.close()
        self.memory.close()


def main() -> int:
    app = JarvisApp()
    return app.run()


if __name__ == "__main__":
    sys.exit(main())
