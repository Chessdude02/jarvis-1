from __future__ import annotations

import sqlite3

from jarvis.security.audit import AuditLog


def test_append_and_read(tmp_path):
    log = AuditLog(tmp_path / "audit.db")
    log.record("test_event", tool="get_memory_usage", success=True)
    log.record("test_event", tool="execute_command", success=False)
    events = list(log.iter_events())
    assert len(events) == 2
    assert events[0].data["tool"] == "get_memory_usage"
    assert events[1].data["tool"] == "execute_command"
    log.close()


def test_chain_links_each_row_to_the_previous(tmp_path):
    log = AuditLog(tmp_path / "audit.db")
    log.record("a")
    log.record("b")
    events = list(log.iter_events())
    assert events[1].prev_hash == events[0].hash
    log.close()


def test_verify_chain_ok_on_untampered_log(tmp_path):
    log = AuditLog(tmp_path / "audit.db")
    for i in range(5):
        log.record("event", i=i)
    ok, bad_id = log.verify_chain()
    assert ok is True
    assert bad_id is None
    log.close()


def test_verify_chain_detects_tampering(tmp_path):
    db_path = tmp_path / "audit.db"
    log = AuditLog(db_path)
    log.record("a", value="original")
    log.record("b", value="second")
    log.close()

    # Simulate someone editing the SQLite file directly, bypassing AuditLog's
    # own (delete/update-free) API entirely.
    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE audit_log SET data = ? WHERE id = 1", ('{"value": "tampered"}',))
    conn.commit()
    conn.close()

    log2 = AuditLog(db_path)
    ok, bad_id = log2.verify_chain()
    assert ok is False
    assert bad_id == 1
    log2.close()


def test_audit_log_exposes_no_delete_or_update_api():
    public_methods = {name for name in dir(AuditLog) if not name.startswith("_")}
    assert "delete" not in public_methods
    assert "update" not in public_methods
    assert "clear" not in public_methods
    assert "truncate" not in public_methods
