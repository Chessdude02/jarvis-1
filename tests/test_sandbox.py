from __future__ import annotations

import sys
import time

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="uses posix shell built-ins; Windows path uses cmd /c and is exercised manually")


def test_run_simple_command_success(sandbox, tmp_path):
    result = sandbox.run("echo hello", str(tmp_path))
    assert result.return_code == 0
    assert "hello" in result.stdout
    assert not result.timed_out
    assert not result.truncated


def test_run_failing_command_reports_nonzero_exit(sandbox, tmp_path):
    result = sandbox.run("exit 7", str(tmp_path))
    assert result.return_code == 7


def test_timeout_kills_long_running_process(settings, tmp_path):
    from jarvis.security.sandbox import Sandbox
    settings.limits.max_command_execution_seconds = 1
    sandbox = Sandbox(settings)
    start = time.monotonic()
    result = sandbox.run("sleep 10", str(tmp_path))
    elapsed = time.monotonic() - start
    assert result.timed_out is True
    assert elapsed < 5  # killed well before the full 10s sleep


def test_output_is_truncated_at_configured_limit(settings, tmp_path):
    from jarvis.security.sandbox import Sandbox
    settings.limits.max_output_bytes = 100
    sandbox = Sandbox(settings)
    result = sandbox.run("yes x | head -c 100000", str(tmp_path))
    assert result.truncated is True
    assert len(result.stdout.encode("utf-8")) < 100_000


def test_subprocess_count_limit_refuses_extra_commands(settings, tmp_path):
    from jarvis.security.sandbox import Sandbox
    import threading

    settings.limits.max_subprocess_count = 1
    settings.limits.max_command_execution_seconds = 5
    sandbox = Sandbox(settings)

    results = {}

    def run_long():
        results["long"] = sandbox.run("sleep 2", str(tmp_path))

    t = threading.Thread(target=run_long)
    t.start()
    time.sleep(0.3)  # let the first command actually start

    second = sandbox.run("echo should-be-refused", str(tmp_path))
    assert second.error is not None
    assert "already running" in second.error

    t.join()


def test_nonexistent_cwd_is_rejected(sandbox, tmp_path):
    result = sandbox.run("echo hi", str(tmp_path / "does_not_exist"))
    assert result.error is not None


def test_emergency_stop_kills_active_processes(settings, tmp_path):
    from jarvis.security.sandbox import Sandbox
    import threading

    settings.limits.max_command_execution_seconds = 30
    settings.limits.max_subprocess_count = 10
    sandbox = Sandbox(settings)
    results = []

    def run_long():
        results.append(sandbox.run("sleep 15", str(tmp_path)))

    threads = [threading.Thread(target=run_long) for _ in range(8)]
    for t in threads:
        t.start()
    time.sleep(0.5)
    assert sandbox.active_count == 8

    killed = sandbox.emergency_stop_all()
    assert killed == 8
    for t in threads:
        t.join(timeout=10)
    assert sandbox.active_count == 0
    assert all(r.return_code != 0 for r in results), "a concurrently running command survived emergency stop"
    assert sandbox.active_count == 0
