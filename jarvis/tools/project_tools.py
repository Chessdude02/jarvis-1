"""Project discovery / indexing.

Builds a lightweight index of "things that look like a project" under the
user's configured indexed_roots, without requiring the user to register
each path individually. A directory is treated as a project root if it
contains a recognizable project marker (.git, requirements.txt,
pyproject.toml, package.json, pom.xml, Cargo.toml, go.mod, .csproj/.sln).

The index is a plain list of dicts, cheap to rebuild, and is cached on the
ToolContext (context.project_index) by the orchestrator so repeated
searches in one session don't rescan the disk. There is no fuzzy magic here
that pretends certainty: search_projects returns every candidate match with
a simple confidence score, and the caller (LLM) is expected to say so when
there's more than one.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from difflib import SequenceMatcher

from jarvis.security.permissions import PermissionLevel
from jarvis.tools import path_guard
from jarvis.tools.base import Tool, ToolContext, ToolResult

_MARKER_TO_TYPE = {
    ".git": "git-repo",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "setup.py": "python",
    "package.json": "node",
    "pom.xml": "java-maven",
    "build.gradle": "java-gradle",
    "Cargo.toml": "rust",
    "go.mod": "go",
}

_LANGUAGE_EXTENSIONS = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".java": "Java", ".cs": "C#", ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
    ".cpp": "C++", ".c": "C", ".php": "PHP",
}

_IMPORTANT_FILES = {
    "readme.md", "readme.txt", "readme", "license", "dockerfile",
    "docker-compose.yml", "requirements.txt", "pyproject.toml", "package.json",
    ".env.example", "makefile",
}
_ENV_FILE_NAMES = {".env", ".env.example", ".env.local", "config.yaml", "config.yml", "settings.ini"}


@dataclass
class ProjectRecord:
    name: str
    path: str
    project_type: str
    has_git: bool
    languages: list[str] = field(default_factory=list)
    important_files: list[str] = field(default_factory=list)
    last_modified: str = ""
    size_bytes: int = 0
    has_readme: bool = False
    env_files: list[str] = field(default_factory=list)


def _has_marker(entries: set[str]) -> str | None:
    for marker, ptype in _MARKER_TO_TYPE.items():
        if marker in entries:
            return ptype
    return None


def _scan_project(project_dir) -> ProjectRecord:
    languages: set[str] = set()
    important: list[str] = []
    env_files: list[str] = []
    total_size = 0
    latest_mtime = 0.0
    has_readme = False

    for f in path_guard.walk_bounded(str(project_dir), _ScanLimits, max_depth=6, max_entries=3000):
        try:
            st = f.stat()
        except OSError:
            continue
        total_size += st.st_size
        latest_mtime = max(latest_mtime, st.st_mtime)
        ext = f.suffix.lower()
        if ext in _LANGUAGE_EXTENSIONS:
            languages.add(_LANGUAGE_EXTENSIONS[ext])
        lname = f.name.lower()
        if lname in _IMPORTANT_FILES:
            important.append(f.name)
        if lname.startswith("readme"):
            has_readme = True
        if lname in _ENV_FILE_NAMES:
            env_files.append(f.name)

    entries = {e.lower() for e in os.listdir(project_dir)} if os.path.isdir(project_dir) else set()
    ptype = _has_marker({e for e in os.listdir(project_dir)}) or "unknown"

    return ProjectRecord(
        name=os.path.basename(str(project_dir).rstrip(os.sep)),
        path=str(project_dir),
        project_type=ptype,
        has_git=".git" in entries,
        languages=sorted(languages),
        important_files=sorted(set(important)),
        last_modified=datetime.fromtimestamp(latest_mtime).isoformat(timespec="seconds") if latest_mtime else "",
        size_bytes=total_size,
        has_readme=has_readme,
        env_files=sorted(set(env_files)),
    )


class _ScanLimits:
    """Tighter, fixed limits used only for the inner project scan, independent
    of the caller's search limits, so indexing one project can't itself
    balloon into an unbounded walk."""

    excluded_dirs = [
        ".git", "node_modules", "__pycache__", ".venv", "venv", "site-packages",
        "dist", "build", ".mypy_cache", ".pytest_cache",
    ]

    class limits:
        max_recursive_depth = 6
        max_files_scanned_per_search = 3000


def build_index(settings) -> list[ProjectRecord]:
    records: list[ProjectRecord] = []
    seen_paths: set[str] = set()
    for root in settings.indexed_roots:
        err = path_guard.check_readable(root, settings)
        if err or not os.path.isdir(root):
            continue
        try:
            top_entries = os.scandir(root)
        except OSError:
            continue
        for entry in top_entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            if entry.name.lower() in {e.lower() for e in settings.excluded_dirs}:
                continue
            try:
                dir_entries = set(os.listdir(entry.path))
            except OSError:
                continue
            ptype = _has_marker(dir_entries)
            if ptype is None:
                continue
            if entry.path in seen_paths:
                continue
            seen_paths.add(entry.path)
            records.append(_scan_project(entry.path))
    return records


def _confidence(query: str, name: str, path: str) -> float:
    q = query.lower()
    n = name.lower()
    if q == n:
        return 1.0
    if q in n or n in q:
        return 0.85
    ratio = SequenceMatcher(None, q, n).ratio()
    if q in path.lower():
        ratio = max(ratio, 0.7)
    return round(ratio, 2)


class SearchProjectsTool(Tool):
    name = "search_projects"
    category = PermissionLevel.SAFE
    description = "Find a project by name across the configured indexed roots (e.g. 'Where is my Neo4j project?'). Returns ranked candidates, not a single guaranteed answer."
    parameters = {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}

    def execute(self, args, context: ToolContext) -> ToolResult:
        index = context.project_index or []
        query = args["query"]
        scored = [(_confidence(query, r.name, r.path), r) for r in index]
        scored = [s for s in scored if s[0] >= 0.3]
        scored.sort(key=lambda s: s[0], reverse=True)
        top = scored[:5]
        if not top:
            return ToolResult(True, {"matches": []}, facts=[f"No project matching '{query}' was found in the indexed roots."])
        facts = [f"{len(top)} candidate match(es) for '{query}' (highest confidence first):"]
        facts += [f"  {r.path} (confidence {c})" for c, r in top]
        return ToolResult(True, {"matches": [{"confidence": c, **asdict(r)} for c, r in top]}, facts=facts)


class GetProjectInfoTool(Tool):
    name = "get_project_info"
    category = PermissionLevel.SAFE
    description = "Get full indexed details (languages, git status, size, README, env files) for a project by exact path."
    parameters = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}

    def build_request(self, args):
        req = super().build_request(args)
        req.paths = [args.get("path", "")]
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        err = path_guard.check_readable(args["path"], context.settings)
        if err:
            return ToolResult(False, error=err, facts=[f"I can't inspect that path: {err}"])
        index = context.project_index or []
        for r in index:
            if os.path.normcase(r.path) == os.path.normcase(args["path"]):
                return ToolResult(True, asdict(r), facts=[f"{r.name}: {r.project_type}, languages={r.languages}, git={r.has_git}, README={r.has_readme}."])
        record = _scan_project(args["path"])
        return ToolResult(True, asdict(record), facts=[f"{record.name}: {record.project_type}, languages={record.languages}, git={record.has_git}, README={record.has_readme}. (Not in the cached index; scanned on demand.)"])


TOOLS = [SearchProjectsTool(), GetProjectInfoTool()]
