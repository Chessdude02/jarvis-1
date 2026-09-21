"""The chat panel: conversation, tool activity, plans, and errors. Appears
beside the entity when it's clicked. Kept deliberately simple (a text log +
a single-line input) -- this is the "transparent" surface the spec asks
for, not a rich chat product.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QTextCursor
from PySide6.QtWidgets import QLineEdit, QPushButton, QTextEdit, QVBoxLayout, QWidget

_DARK_STYLE = """
QWidget { background-color: #12151c; color: #e6ecf5; font-family: 'Segoe UI', sans-serif; font-size: 12px; }
QTextEdit { background-color: #0c0f14; border: 1px solid #2a3040; border-radius: 6px; padding: 6px; }
QLineEdit { background-color: #1a1f2b; border: 1px solid #2a3040; border-radius: 6px; padding: 6px; }
QPushButton { background-color: #2b6cb0; border: none; border-radius: 6px; padding: 6px 12px; color: white; }
QPushButton:hover { background-color: #3182ce; }
QPushButton:disabled { background-color: #2a3040; color: #666; }
"""

_ROLE_COLORS = {
    "user": "#8fd3ff",
    "assistant": "#e6ecf5",
    "tool": "#8fffb0",
    "plan": "#ffd27f",
    "error": "#ff8f8f",
    "system": "#9aa3b0",
}


class ChatWindow(QWidget):
    message_sent = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setStyleSheet(_DARK_STYLE)
        self.setFixedSize(420, 520)

        self.log = QTextEdit(self)
        self.log.setReadOnly(True)

        self.input = QLineEdit(self)
        self.input.setPlaceholderText("Ask JARVIS...")
        self.input.returnPressed.connect(self._on_send)

        self.send_button = QPushButton("Send", self)
        self.send_button.clicked.connect(self._on_send)

        layout = QVBoxLayout(self)
        layout.addWidget(self.log)
        input_row = QWidget(self)
        from PySide6.QtWidgets import QHBoxLayout
        h = QHBoxLayout(input_row)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(self.input)
        h.addWidget(self.send_button)
        layout.addWidget(input_row)

    def _on_send(self) -> None:
        text = self.input.text().strip()
        if not text:
            return
        self.append("user", text)
        self.input.clear()
        self.set_input_enabled(False)
        self.message_sent.emit(text)

    def set_input_enabled(self, enabled: bool) -> None:
        self.input.setEnabled(enabled)
        self.send_button.setEnabled(enabled)
        if enabled:
            self.input.setFocus()

    def append(self, role: str, text: str) -> None:
        color = _ROLE_COLORS.get(role, "#e6ecf5")
        label = {"user": "You", "assistant": "JARVIS", "tool": "Tool", "plan": "Plan", "error": "Error", "system": "System"}.get(role, role)
        safe = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
        self.log.append(f"<div style='margin-bottom:6px;'><b style='color:{color}'>{label}:</b><br>{safe}</div>")
        self.log.moveCursor(QTextCursor.End)
