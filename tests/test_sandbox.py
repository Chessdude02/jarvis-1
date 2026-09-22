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


def test_invalid_utf8_output_does_not_silently_lose_the_result(sandbox, tmp_path):
    # Found by testing: default text-mode decoding is strict, so any
    # command emitting a non-UTF-8 byte sequence (a binary tool, a
    # different-locale program) raised an uncaught UnicodeDecodeError
    # inside the background _drain thread. Threads swallow unhandled
    # exceptions, so this silently killed output capture and returned
    # success=True with an EMPTY stdout -- a fabricated-looking clean
    # result instead of a visible failure. Must now preserve the
    # surrounding valid text with the invalid bytes replaced, not vanish.
    cmd = ("python3 -c \"import sys; sys.stdout.buffer.write("
           "bytes([0x62,0x65,0x66,0x6f,0x72,0x65,0xff,0xfe,0x61,0x66,0x74,0x65,0x72,0x0a]))\"")
    result = sandbox.run(cmd, str(tmp_path))
    assert result.return_code == 0
    assert "before" in result.stdout
    assert "after" in result.stdout
    assert result.stdout != ""


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


def test_output_with_no_newlines_is_still_bounded_in_memory(settings, tmp_path):
    # Regression test for a real memory-exhaustion DoS: pipe.readline()
    # blocks and keeps growing its own internal buffer until it sees a
    # newline OR EOF, so a process that writes large chunks with NO '\n'
    # at all never gave readline() a chance to return -- the
    # "total > max_bytes" truncation check never ran until the process was
    # finally killed by the (separate) timeout, by which point everything
    # written had already accumulated in memory as one giant "line".
    # Found by testing: with max_output_bytes=1000, this command pushed
    # RSS up by ~700MB before truncation kicked in. Must now be caught
    # almost immediately, well before the timeout, via bounded chunk reads.
    import resource

    from jarvis.security.sandbox import Sandbox

    settings.limits.max_output_bytes = 1000
    settings.limits.max_command_execution_seconds = 3
    sandbox = Sandbox(settings)

    mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    cmd = "python3 -c \"import sys; [sys.stdout.write('A'*1000000) for _ in range(1000)]\""
    result = sandbox.run(cmd, str(tmp_path))
    mem_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    assert result.truncated is True
    assert result.timed_out is False  # caught by the size check, not the timeout
    assert result.duration_seconds < 1.0  # truncated almost immediately, not after the full timeout
    assert (mem_after - mem_before) < 50 * 1024  # well under 50MB growth, not ~700MB


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
