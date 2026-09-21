"""Shared filesystem-safety helpers used by every tool that touches disk.

Two independent checks, both must pass:
  - the path must resolve inside one of settings.indexed_roots (opt-in
    allowlist the user configured), and
  - it must not fall under settings.system_deny_roots or a credential
    path fragment (the deny_list checks the policy engine also runs --
    duplicated here so a tool refuses to even build a result before the
    policy engine is consulted, e.g. when just enumerating candidates).

Also provides a depth/count-bounded directory walker so no single tool call
can be turned into an unbounded scan of the whole drive.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from jarvis.security import deny_list


def resolve(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path))).resolve()


def is_within_indexed_roots(path: str, settings) -> bool:
    try:
        target = resolve(path)
    except (OSError, RuntimeError):
        return False
    for root in settings.indexed_roots:
        try:
            root_path = resolve(root)
        except (OSError, RuntimeError):
            continue
        if target == root_path or root_path in target.parents:
            return True
    return False


def is_denied(path: str, settings) -> str | None:
    return deny_list.denied_path(str(path)) or deny_list.denied_system_root(str(path), settings.system_deny_roots)


def check_readable(path: str, settings) -> str | None:
    """Returns an error string if the path may not be read, else None."""
    reason = is_denied(path, settings)
    if reason:
        return reason
    if not is_within_indexed_roots(path, settings):
        return f"Path is outside all configured indexed roots: {settings.indexed_roots}."
    return None


def _is_excluded(dirname: str, settings) -> bool:
    lowered = dirname.lower()
    return any(lowered == ex.lower() for ex in settings.excluded_dirs)


def walk_bounded(root: str, settings, max_depth: int | None = None, max_entries: int | None = None) -> Iterator[Path]:
    """Yields file Paths under root, respecting excluded_dirs, the configured
    max_recursive_depth, and max_files_scanned_per_search. Never follows
    symlinks (avoids escaping indexed roots via a link).
    """
    max_depth = max_depth if max_depth is not None else settings.limits.max_recursive_depth
    max_entries = max_entries if max_entries is not None else settings.limits.max_files_scanned_per_search
    root_path = resolve(root)
    count = 0

    def _walk(current: Path, depth: int) -> Iterator[Path]:
        nonlocal count
        if depth > max_depth or count >= max_entries:
            return
        try:
            entries = list(os.scandir(current))
        except (PermissionError, OSError):
            return
        for entry in entries:
            if count >= max_entries:
                return
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if _is_excluded(entry.name, settings):
                    continue
                yield from _walk(Path(entry.path), depth + 1)
            elif entry.is_file(follow_symlinks=False):
                count += 1
                yield Path(entry.path)

    yield from _walk(root_path, 0)
