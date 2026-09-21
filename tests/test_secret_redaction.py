"""Secret redaction is a deterministic scanner (jarvis.security.secrets),
applied at two independent points: AuditLog.record() itself (so no caller
can forget to redact before something becomes durable and append-only), and
inside execute_command (so a leaked key in command output never reaches the
live chat display or the LLM's own context either).
"""
from __future__ import annotations

import sys

import pytest

from jarvis.security.secrets import contains_secret, redact, redact_value


def test_redact_curated_secret_shapes():
    samples_and_markers = [
        ("my key is sk-abcdefghijklmnopqrstuvwx1234", "sk-"),
        ("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP", "AKIA"),
        ("github token: ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----", "PRIVATE KEY"),
        ('password: "SuperSecret123!"', "password"),
        ("api_key=abcdef12345678", "api_key"),
        ("postgres://user:hunter2@db.example.com:5432/mydb", "postgres://"),
    ]
    for text, marker in samples_and_markers:
        result = redact(text)
        assert "[REDACTED]" in result, f"{marker} shape was not redacted: {text!r} -> {result!r}"


def test_normal_text_is_untouched():
    text = "Your RAM usage is 4.2 GB out of 16 GB (26%)."
    assert redact(text) == text


def test_contains_secret_detector():
    assert contains_secret("token: abcdefghijklmnop") is True
    assert contains_secret("just a normal sentence") is False


def test_redact_value_recurses_through_nested_structures():
    data = {
        "stdout": "deploying with api_key=abcdef12345678",
        "nested": {"note": "safe", "leak": "AKIAABCDEFGHIJKLMNOP"},
        "list": ["fine", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
        "number": 42,
    }
    result = redact_value(data)
    assert "[REDACTED]" in result["stdout"]
    assert result["nested"]["note"] == "safe"
    assert "[REDACTED]" in result["nested"]["leak"]
    assert result["list"][0] == "fine"
    assert "[REDACTED]" in result["list"][1]
    assert result["number"] == 42


def test_audit_log_redacts_secrets_before_storing(tmp_path):
    from jarvis.security.audit import AuditLog

    log = AuditLog(tmp_path / "audit.db")
    log.record("policy_decision", command='curl -H "Authorization: Bearer sk-abcdefghijklmnopqrstuvwx" https://api.example.com')
    events = list(log.iter_events())
    stored_command = events[0].data["command"]
    assert "sk-abcdefghijklmnopqrstuvwx" not in stored_command
    assert "[REDACTED]" in stored_command
    log.close()


@pytest.mark.skipif(sys.platform == "win32", reason="uses posix shell built-ins")
def test_execute_command_redacts_stdout_before_becoming_a_fact(settings, sandbox):
    from jarvis.tools.terminal_tools import ExecuteCommandTool
    from jarvis.tools.base import ToolContext

    tool = ExecuteCommandTool()
    ctx = ToolContext(settings=settings, sandbox=sandbox)
    project = settings.indexed_roots[0]
    result = tool.execute({"command": "echo api_key=abcdef12345678", "cwd": project}, ctx)

    joined_facts = "\n".join(result.facts)
    assert "abcdef12345678" not in joined_facts
    assert "[REDACTED]" in joined_facts
    assert "abcdef12345678" not in result.data["stdout"]
