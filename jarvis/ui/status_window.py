"""The "JARVIS status" panel, matching the spec's example layout."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

_STYLE = """
QWidget { background-color: #12151c; color: #e6ecf5; font-family: Consolas, monospace; font-size: 12px; }
QLabel#heading { font-size: 15px; font-weight: bold; color: #7fd0ff; }
"""


class StatusWindow(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setStyleSheet(_STYLE)
        self.setFixedSize(320, 320)
        layout = QVBoxLayout(self)
        heading = QLabel("JARVIS", self)
        heading.setObjectName("heading")
        layout.addWidget(heading)
        self.body = QLabel("", self)
        self.body.setTextFormat(Qt.RichText)
        layout.addWidget(self.body)
        layout.addStretch()

    def update_status(self, data: dict) -> None:
        checks = "".join(
            f"<div>{'&#10003;' if v else '&#10007;'} {k}</div>"
            for k, v in data.get("security", {}).items()
        )
        html = f"""
        <div>LLM: {data.get('llm_status', 'unknown')}</div>
        <div>Model: {data.get('model', '')}</div>
        <div>CPU: {data.get('cpu_percent', '?')}%</div>
        <div>RAM: {data.get('ram_gb', '?')} GB</div>
        <div>Tools: {data.get('tool_count', 0)} enabled</div>
        <div>Network: {data.get('network', 'Disabled')}</div>
        <div>Pending approvals: {data.get('pending_approvals', 0)}</div>
        <br><div><b>Security:</b></div>
        {checks}
        """
        self.body.setText(html)
