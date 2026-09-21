"""Bounded execution of approved shell commands.

By the time anything reaches Sandbox.run(), the policy engine has already
decided ALLOW/CONFIRM(+approved). This module's only job is to make sure
that even a fully-approved, legitimate command cannot runaway: hard timeout,
output-size cap, a concurrent-process ceiling, a filtered environment, and a
working-directory that the caller must supply explicitly (Sandbox does not
default to the repo root or the user's home directory).
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field

_SAFE_ENV_PREFIXES = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC",
    "TEMP", "TMP", "USERPROFILE", "USERNAME", "HOMEDRIVE", "HOMEPATH",
    "PROGRAMFILES", "PROGRAMDATA", "APPDATA", "LOCALAPPDATA",
    "PYTHONIOENCODING", "PYTHONUTF8", "LANG", "LC_ALL",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS",
    "NODE_ENV", "VIRTUAL_ENV",
)
_DENY_ENV_SUBSTRINGS = ("key", "secret", "token", "password", "credential", "auth")


def _filtered_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for name, value in os.environ.items():
        upper = name.upper()
        if any(bad in upper.lower() for bad in _DENY_ENV_SUBSTRINGS):
            continue
        if upper.startswith(_SAFE_ENV_PREFIXES):
            env[name] = value
    return env


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kills the whole process tree rooted at proc, not just the PID Python
    is tracking. A plain proc.kill() only kills the immediate child (the
    shell); anything that shell forked -- rather than exec'd into -- keeps
    running as an orphan and keeps the output pipe open, which is exactly
    how a naive implementation of this defeats its own timeout.
    """
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, timeout=10,
            )
        except Exception:
            pass
        try:
            proc.kill()
        except Exception:
            pass
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass


@dataclass
class SandboxResult:
    execution_id: str
    return_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False
    duration_seconds: float = 0.0
    error: str | None = None


class Sandbox:
    def __init__(self, settings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._active: dict[str, subprocess.Popen] = {}

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._active)

    def most_recent_execution_id(self) -> str | None:
        """Used by kill-switch Level 1 ('cancel current action', as opposed
        to Level 2's 'stop everything'). dict insertion order is reliable in
        Python 3.7+, so the last key is the most recently started execution.
        """
        with self._lock:
            keys = list(self._active.keys())
            return keys[-1] if keys else None

    def run(self, command: str, cwd: str) -> SandboxResult:
        limits = self.settings.limits
        execution_id = uuid.uuid4().hex[:12]

        with self._lock:
            if len(self._active) >= limits.max_subprocess_count:
                return SandboxResult(
                    execution_id, None, "", "",
                    error=f"Refused: {len(self._active)} commands already running "
                          f"(max_subprocess_count={limits.max_subprocess_count}).",
                )

        if not os.path.isdir(cwd):
            return SandboxResult(execution_id, None, "", "", error=f"Working directory does not exist: {cwd}")

        popen_kwargs: dict = {}
        if sys.platform == "win32":
            argv = ["cmd", "/d", "/c", command]
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            argv = ["/bin/sh", "-c", command]
            # New session/process group: a shell command that forks children
            # (e.g. "sleep 10" under dash, or any multi-process build tool)
            # leaves those children in this group too, so killing the group
            # -- not just the tracked PID -- actually stops the whole tree.
            popen_kwargs["start_new_session"] = True

        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                env=_filtered_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                # Default text-mode decoding is strict: a command emitting
                # any byte sequence that isn't valid UTF-8 (a binary tool, a
                # crash dump, a different-locale program) raised an uncaught
                # UnicodeDecodeError inside the _drain thread below. Threads
                # swallow unhandled exceptions silently, so this didn't
                # crash the app -- it silently killed output capture
                # entirely and returned success=True with empty stdout,
                # which is worse: a fabricated-looking clean result instead
                # of a visible failure. "replace" keeps decoding instead of
                # aborting, substituting U+FFFD for bad bytes.
                errors="replace",
                bufsize=1,
                **popen_kwargs,
            )
        except OSError as exc:
            return SandboxResult(execution_id, None, "", "", error=f"Failed to start process: {exc}")

        with self._lock:
            self._active[execution_id] = proc

        max_bytes = limits.max_output_bytes
        out_chunks: list[str] = []
        err_chunks: list[str] = []
        truncated = {"flag": False}

        def _drain(pipe, sink: list[str]) -> None:
            total = 0
            for line in iter(pipe.readline, ""):
                total += len(line.encode("utf-8", errors="ignore"))
                if total > max_bytes:
                    truncated["flag"] = True
                    _kill_tree(proc)
                    break
                sink.append(line)
            pipe.close()

        t_out = threading.Thread(target=_drain, args=(proc.stdout, out_chunks), daemon=True)
        t_err = threading.Thread(target=_drain, args=(proc.stderr, err_chunks), daemon=True)
        t_out.start()
        t_err.start()

        timed_out = False
        try:
            proc.wait(timeout=limits.max_command_execution_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(proc)
            try:
                proc.wait(timeout=5)
            except Exception:
                pass

        t_out.join(timeout=5)
        t_err.join(timeout=5)

        with self._lock:
            self._active.pop(execution_id, None)

        duration = time.monotonic() - start
        return SandboxResult(
            execution_id=execution_id,
            return_code=proc.returncode,
            stdout="".join(out_chunks),
            stderr="".join(err_chunks),
            timed_out=timed_out,
            truncated=truncated["flag"],
            duration_seconds=duration,
        )

    def terminate(self, execution_id: str) -> bool:
        with self._lock:
            proc = self._active.get(execution_id)
        if proc is None:
            return False
        _kill_tree(proc)
        return True

    def emergency_stop_all(self) -> int:
        """Kills every active sandboxed process immediately. Independent of
        the LLM/orchestrator -- the UI calls this directly on the hotkey.
        """
        with self._lock:
            procs = list(self._active.values())
            self._active.clear()
        killed = 0
        for proc in procs:
            try:
                _kill_tree(proc)
                killed += 1
            except Exception:
                pass
        return killed
