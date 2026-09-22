"""The approval action card. This is the literal UI the spec's mockup
describes: WHAT, WHERE, the exact command, and the risk level, never a vague
"I'll take care of it". Buttons map 1:1 to ApprovalScope so there is no
"allow everything" option -- only ONCE / SESSION / a narrow ALWAYS grant
scoped by the tool's own grant_key, or DENY/CANCEL.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QTextEdit, QVBoxLayout

from jarvis.security.permissions import ActionRequest, ApprovalScope, PermissionLevel, PolicyDecision, Reversibility

_RISK_COLORS = {"LOW": "#7fd18f", "MEDIUM": "#ffd27f", "HIGH": "#ff9d5c", "CRITICAL": "#ff6b6b"}
_REVERSIBILITY_COLORS = {
    Reversibility.REVERSIBLE: "#7fd18f",
    Reversibility.PARTIALLY_REVERSIBLE: "#ffd27f",
    Reversibility.IRREVERSIBLE: "#ff6b6b",
    Reversibility.UNKNOWN: "#9aa3b0",
}

_STYLE = """
QDialog { background-color: #12151c; color: #e6ecf5; font-family: 'Segoe UI', sans-serif; }
QLabel { color: #e6ecf5; }
QLabel#title { font-size: 14px; font-weight: bold; color: #ffb347; }
QTextEdit { background-color: #0c0f14; border: 1px solid #2a3040; border-radius: 6px; padding: 6px; color: #cfe8ff; font-family: Consolas, monospace; }
QPushButton { border: none; border-radius: 6px; padding: 8px 14px; color: white; }
QPushButton#approve { background-color: #2b6cb0; }
QPushButton#approve:hover { background-color: #3182ce; }
QPushButton#deny { background-color: #b03030; }
QPushButton#deny:hover { background-color: #c94040; }
QPushButton#neutral { background-color: #2a3040; }
QPushButton#neutral:hover { background-color: #38405a; }
"""


class ApprovalDialog(QDialog):
    def __init__(self, request: ActionRequest, decision: PolicyDecision, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("JARVIS - Action Requires Approval")
        self.setStyleSheet(_STYLE)
        self.setFixedWidth(440)
        self._scope = ApprovalScope.CANCEL

        layout = QVBoxLayout(self)
        title = QLabel("ACTION REQUIRES APPROVAL", self)
        title.setObjectName("title")
        layout.addWidget(title)

        layout.addWidget(QLabel(request.description or request.tool_name, self))

        if request.cwd or request.paths:
            location = request.cwd or (request.paths[0] if request.paths else "")
            layout.addWidget(QLabel(f"Location:\n{location}", self))

        if request.command:
            # Found by testing: a fixed 50px box needs a scrollbar for any
            # command longer than ~2 short lines -- confirmed with a
            # realistic 253-char chained command whose dangerous "rm -rf"
            # suffix sat well past the fold, invisible without actively
            # scrolling a small, easy-to-miss box. That directly undermines
            # this dialog's own stated purpose ("the exact command, never a
            # vague 'I'll take care of it'"): a user glancing at the
            # visible prefix and approving would never see the payload.
            # Sized to the actual content instead, up to a generous cap --
            # short commands (the overwhelming majority) show in full with
            # no wasted space; a command still too long for the cap gets an
            # explicit, hard-to-miss warning rather than a bare scrollbar.
            cmd_box = QTextEdit(self)
            cmd_box.setReadOnly(True)
            cmd_box.setText(request.command)
            _MAX_CMD_BOX_HEIGHT = 220
            _MIN_CMD_BOX_HEIGHT = 40
            # The box isn't laid out yet at __init__ time, so its document
            # would otherwise measure word-wrap against a stale/default
            # width and under-report how tall the content actually needs to
            # be (found by testing: this returned the same tiny height for
            # a 10-char and a 2000-char command alike). The dialog itself is
            # a fixed width, so the eventual content width is already known
            # -- set it explicitly before measuring.
            content_width = self.width() - 40
            cmd_box.document().setTextWidth(content_width)
            content_height = int(cmd_box.document().size().height()) + 12
            cmd_box.setFixedHeight(max(_MIN_CMD_BOX_HEIGHT, min(content_height, _MAX_CMD_BOX_HEIGHT)))
            layout.addWidget(cmd_box)
            if content_height > _MAX_CMD_BOX_HEIGHT:
                overflow_warning = QLabel(
                    "⚠ This command is longer than fits above -- scroll the box to review it in full before approving.",
                    self,
                )
                overflow_warning.setStyleSheet("color: #ffb347; font-weight: bold;")
                overflow_warning.setWordWrap(True)
                layout.addWidget(overflow_warning)

        risk_color = _RISK_COLORS.get(decision.risk.value, "#e6ecf5")
        risk_label = QLabel(f"Risk: <span style='color:{risk_color}'>{decision.risk.value}</span> ({decision.category.value})", self)
        risk_label.setTextFormat(Qt.RichText)
        layout.addWidget(risk_label)

        rev_color = _REVERSIBILITY_COLORS.get(request.reversibility, "#e6ecf5")
        rev_label = QLabel(f"Reversibility: <span style='color:{rev_color}'>{request.reversibility.value}</span>", self)
        rev_label.setTextFormat(Qt.RichText)
        layout.addWidget(rev_label)

        if decision.reasons:
            reasons = QLabel("Why: " + "; ".join(decision.reasons), self)
            reasons.setWordWrap(True)
            layout.addWidget(reasons)

        button_row = QHBoxLayout()
        approve_once = QPushButton("Approve Once", self)
        approve_once.setObjectName("approve")
        approve_once.clicked.connect(lambda: self._choose(ApprovalScope.ONCE))
        button_row.addWidget(approve_once)

        if decision.category == PermissionLevel.MODIFY and request.grant_key:
            approve_session = QPushButton("Approve This Session", self)
            approve_session.setObjectName("neutral")
            approve_session.clicked.connect(lambda: self._choose(ApprovalScope.SESSION))
            button_row.addWidget(approve_session)

            approve_always = QPushButton("Always Allow This Action", self)
            approve_always.setObjectName("neutral")
            approve_always.clicked.connect(lambda: self._choose(ApprovalScope.ALWAYS_THIS_ACTION))
            button_row.addWidget(approve_always)

        layout.addLayout(button_row)

        bottom_row = QHBoxLayout()
        deny = QPushButton("Deny", self)
        deny.setObjectName("deny")
        deny.clicked.connect(lambda: self._choose(ApprovalScope.DENY))
        cancel = QPushButton("Cancel", self)
        cancel.setObjectName("neutral")
        cancel.clicked.connect(lambda: self._choose(ApprovalScope.CANCEL))
        bottom_row.addWidget(deny)
        bottom_row.addWidget(cancel)
        layout.addLayout(bottom_row)

    def _choose(self, scope: ApprovalScope) -> None:
        self._scope = scope
        self.accept()

    @staticmethod
    def ask(parent, request: ActionRequest, decision: PolicyDecision) -> ApprovalScope:
        dialog = ApprovalDialog(request, decision, parent)
        dialog.exec()
        return dialog._scope
