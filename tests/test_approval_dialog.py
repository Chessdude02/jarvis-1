"""ApprovalDialog is the one place a person actually sees, and approves or
denies, the exact command JARVIS is about to run. Its own module docstring
states the design goal explicitly: "the exact command... never a vague
'I'll take care of it'". These tests confirm that's actually true under
Qt's offscreen platform, not just asserted in a comment.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QTextEdit  # noqa: E402

from jarvis.security.permissions import (  # noqa: E402
    ActionRequest,
    Decision,
    PermissionLevel,
    PolicyDecision,
    Reversibility,
    RiskLevel,
)
from jarvis.ui.approval_dialog import ApprovalDialog  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def _make_dialog(qapp, command: str) -> ApprovalDialog:
    req = ActionRequest(
        tool_name="execute_command", command=command, cwd="/home/user/project",
        reversibility=Reversibility.IRREVERSIBLE,
    )
    decision = PolicyDecision(
        Decision.CONFIRM, PermissionLevel.DESTRUCTIVE, RiskLevel.HIGH,
        ["Command chains, pipes, or redirects multiple operations; not individually verifiable."],
    )
    dialog = ApprovalDialog(req, decision)
    dialog.show()
    qapp.processEvents()
    return dialog


def test_short_command_displays_in_full_without_scrolling(qapp):
    dialog = _make_dialog(qapp, "git status")
    box = dialog.findChildren(QTextEdit)[0]
    assert box.toPlainText() == "git status"
    assert box.verticalScrollBar().maximum() == 0
    dialog.close()


def test_realistic_chained_command_displays_in_full_without_scrolling(qapp):
    # Regression test for a real finding: a fixed 50px command box needed a
    # scrollbar for any command longer than ~2 short lines. Confirmed by
    # testing with exactly this shape of command -- a chain of innocuous
    # "echo build-step-N" segments followed by a destructive tail -- whose
    # "rm -rf" suffix sat well past the fold, invisible without the user
    # actively scrolling a small, easy-to-miss box.
    padding = "echo build-step-one && echo build-step-two && echo build-step-three && "
    cmd = padding * 3 + "rm -rf /home/user/important_project_data"
    dialog = _make_dialog(qapp, cmd)
    box = dialog.findChildren(QTextEdit)[0]
    assert box.toPlainText() == cmd
    assert "rm -rf" in box.toPlainText()
    assert box.verticalScrollBar().maximum() == 0, "the dangerous suffix must not require scrolling to see"
    dialog.close()


def test_pathologically_long_command_still_shows_full_text_and_warns(qapp):
    # A command that genuinely can't fit in any reasonable fixed dialog
    # must still carry the FULL text (a person can scroll to it) and must
    # show an explicit, hard-to-miss warning that scrolling is needed --
    # never a silently truncated/clipped view with no indication more
    # exists.
    padding = "echo build-step-one && echo build-step-two && echo build-step-three && "
    cmd = padding * 30 + "rm -rf /"
    dialog = _make_dialog(qapp, cmd)
    box = dialog.findChildren(QTextEdit)[0]
    assert box.toPlainText() == cmd  # full text always present, even if scrolling is needed to see all of it
    assert box.verticalScrollBar().maximum() > 0
    warning_labels = [l for l in dialog.findChildren(QLabel) if "scroll the box" in l.text()]
    assert warning_labels, "an overflowing command must show an explicit scroll warning"
    dialog.close()


def test_short_command_never_shows_overflow_warning(qapp):
    dialog = _make_dialog(qapp, "pip install requests")
    warning_labels = [l for l in dialog.findChildren(QLabel) if "scroll the box" in l.text()]
    assert not warning_labels
    dialog.close()
