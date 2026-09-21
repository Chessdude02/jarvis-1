"""Filesystem-safety properties, found worth locking in by stress testing:
walk_bounded must terminate against a symlink loop rather than recursing
forever, must actually respect the configured depth/file-count ceilings,
and containment checks must survive a plain '..' traversal attempt.
"""
from __future__ import annotations

import time
from pathlib import Path

from jarvis.tools import path_guard


def test_symlink_loop_does_not_hang_or_inflate_results(settings):
    project = Path(settings.indexed_roots[0])
    loop_dir = project / "loopy"
    loop_dir.mkdir()
    (loop_dir / "self_link").symlink_to(loop_dir, target_is_directory=True)
    (loop_dir / "parent_link").symlink_to(project, target_is_directory=True)
    for i in range(5):
        (loop_dir / f"real_file_{i}.py").write_text("x = 1\n")

    start = time.monotonic()
    files = list(path_guard.walk_bounded(str(project), settings))
    elapsed = time.monotonic() - start

    assert elapsed < 5, "walk_bounded did not terminate quickly against a symlink loop"
    assert len(files) == 5, f"symlink loop was followed, inflating the result count: {len(files)}"


def test_recursion_depth_limit_is_enforced(settings):
    settings.limits.max_recursive_depth = 3
    project = Path(settings.indexed_roots[0])
    current = project / "deep"
    for i in range(20):
        current = current / f"level{i}"
    current.mkdir(parents=True)
    (current / "buried.py").write_text("# too deep\n")
    (project / "deep" / "level0" / "shallow.py").write_text("# within depth\n")

    files = list(path_guard.walk_bounded(str(project), settings))
    names = {f.name for f in files}
    assert "buried.py" not in names
    assert "shallow.py" in names


def test_file_count_limit_is_enforced(settings):
    settings.limits.max_files_scanned_per_search = 50
    project = Path(settings.indexed_roots[0])
    many_dir = project / "many"
    many_dir.mkdir()
    for i in range(300):
        (many_dir / f"f{i}.py").write_text("x\n")

    files = list(path_guard.walk_bounded(str(project), settings))
    assert len(files) <= 50


def test_dotdot_traversal_does_not_escape_indexed_roots(settings):
    project = settings.indexed_roots[0]
    for attempt in (
        project + "/../../../etc/passwd",
        project + "/../../etc/shadow",
    ):
        assert not path_guard.is_within_indexed_roots(attempt, settings), attempt


def test_legitimate_nested_path_is_allowed(settings):
    project = Path(settings.indexed_roots[0])
    nested = project / "sub" / "file.py"
    nested.parent.mkdir(parents=True, exist_ok=True)
    nested.write_text("x\n")
    assert path_guard.is_within_indexed_roots(str(nested), settings)
