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


# -- Gaps found by attack-simulation testing ---------------------------------

def test_redact_stripe_keys():
    # Stripe uses an underscore (sk_live_/sk_test_), not the hyphen the
    # OpenAI/Anthropic-style "sk-" pattern requires -- found by testing:
    # a real Stripe secret key sailed through completely unredacted.
    for text in (
        # Low-entropy placeholders (not shaped like a real issued key) --
        # only need to satisfy the pattern's own character-class/length
        # requirement, not look like a real credential.
        "stripe_key=sk_live_0000000000000000",
        "STRIPE_SECRET=sk_test_0000000000000000",
        "publishable=pk_test_0000000000000000",
    ):
        assert "[REDACTED]" in redact(text), text


def test_redact_keyword_embedded_in_a_longer_identifier():
    # The generic api_key/password/secret/token pattern used to require the
    # ":"/"=" separator IMMEDIATELY after the bare keyword -- found by
    # testing: the overwhelmingly common env-var/config shape, where the
    # keyword is only part of a longer underscore-joined identifier, evaded
    # it entirely ("MY_API_KEY_VALUE=...", "the_token_variable_name_is:...").
    for text in (
        "my_api_key_value = 'abcd1234efgh5678'",
        "the_token_variable_name_is: abcd1234wxyz5678",
        "DATABASE_PASSWORD_HASH=SuperSecretPass123456",
    ):
        assert "[REDACTED]" in redact(text), text


def test_redact_keyword_fix_does_not_false_positive_on_ordinary_prose():
    for text in (
        "primary key constraint violation on table users",
        "git commit -m 'update password reset flow'",
    ):
        assert redact(text) == text, text


def test_ansi_escape_split_secret_is_still_redacted():
    # A raw ANSI escape sequence inserted mid-secret ("sk-abc\x1b[0mdefgh...")
    # broke the character run at the codepoint level the same way a
    # backslash or empty-quote pair broke an attack-tool name -- found by
    # testing. Command output routinely carries real ANSI color codes from
    # build tools, so this is not a contrived shape.
    split_secret = "sk-abc\x1b[0mdefghijklmnopqrstuvwx1234"
    assert "[REDACTED]" in redact(split_secret)
    assert contains_secret(split_secret) is True


def test_ansi_codes_are_stripped_from_ordinary_colorized_output():
    colorized = "\x1b[31mERROR\x1b[0m: build failed normally"
    assert redact(colorized) == "ERROR: build failed normally"


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
