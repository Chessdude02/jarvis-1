"""READ/SAFE filesystem tools. All are read-only against disk and are scoped
to settings.indexed_roots via path_guard -- none of them can be pointed at
an arbitrary drive path outside what the user configured.
"""
from __future__ import annotations

import fnmatch
from datetime import datetime

from jarvis.security.permissions import PermissionLevel
from jarvis.tools import path_guard
from jarvis.tools.base import Tool, ToolContext, ToolResult

_TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".md", ".txt", ".json", ".yaml", ".yml",
    ".toml", ".cfg", ".ini", ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".go",
    ".rs", ".rb", ".php", ".sh", ".ps1", ".sql", ".html", ".css", ".xml",
}


class SearchFilesTool(Tool):
    name = "search_files"
    category = PermissionLevel.SAFE
    description = "Find files by filename pattern within the configured indexed roots."
    parameters = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "description": "Filename glob, e.g. '*.py' or 'settings.py'."},
            "root": {"type": "string", "description": "Optional: restrict to one indexed root."},
        },
        "required": ["pattern"],
    }

    def execute(self, args, context: ToolContext) -> ToolResult:
        pattern = args["pattern"]
        roots = [args["root"]] if args.get("root") else context.settings.indexed_roots
        matches = []
        for root in roots:
            err = path_guard.check_readable(root, context.settings)
            if err:
                continue
            for f in path_guard.walk_bounded(root, context.settings):
                if fnmatch.fnmatch(f.name.lower(), pattern.lower()):
                    matches.append(str(f))
        facts = [f"Found {len(matches)} file(s) matching '{pattern}'."]
        return ToolResult(True, {"matches": matches}, facts=facts)


class SearchFileContentsTool(Tool):
    name = "search_file_contents"
    category = PermissionLevel.SAFE
    description = "Find files whose text content contains a given word/phrase, within the configured indexed roots."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Word or phrase to search for (case-insensitive)."},
            "root": {"type": "string", "description": "Optional: restrict to one indexed root."},
        },
        "required": ["text"],
    }

    def execute(self, args, context: ToolContext) -> ToolResult:
        needle = args["text"].lower()
        roots = [args["root"]] if args.get("root") else context.settings.indexed_roots
        matches = []
        for root in roots:
            err = path_guard.check_readable(root, context.settings)
            if err:
                continue
            for f in path_guard.walk_bounded(root, context.settings):
                if f.suffix.lower() not in _TEXT_EXTENSIONS:
                    continue
                try:
                    if f.stat().st_size > 2_000_000:
                        continue
                    with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                        if needle in fh.read().lower():
                            matches.append(str(f))
                except OSError:
                    continue
        facts = [f"Found {len(matches)} file(s) containing '{args['text']}'."]
        return ToolResult(True, {"matches": matches}, facts=facts)


class ListDirectoryTool(Tool):
    name = "list_directory"
    category = PermissionLevel.SAFE
    description = "List the immediate contents of a directory within the configured indexed roots."
    parameters = {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    }

    def build_request(self, args):
        req = super().build_request(args)
        req.paths = [args.get("path", "")]
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        path = args["path"]
        err = path_guard.check_readable(path, context.settings)
        if err:
            return ToolResult(False, error=err, facts=[f"I can't list that directory: {err}"])
        p = path_guard.resolve(path)
        if not p.is_dir():
            return ToolResult(False, error="Not a directory.", facts=[f"{path} is not a directory."])
        entries = []
        for entry in sorted(p.iterdir(), key=lambda e: e.name.lower()):
            try:
                entries.append({"name": entry.name, "is_dir": entry.is_dir(), "size": entry.stat().st_size if entry.is_file() else None})
            except OSError:
                continue
        facts = [f"{p} contains {len(entries)} entries."]
        return ToolResult(True, {"entries": entries}, facts=facts)


class GetFileMetadataTool(Tool):
    name = "get_file_metadata"
    category = PermissionLevel.READ
    description = "Get size and modified/created timestamps for a file or directory."
    parameters = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}

    def build_request(self, args):
        req = super().build_request(args)
        req.paths = [args.get("path", "")]
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        path = args["path"]
        err = path_guard.check_readable(path, context.settings)
        if err:
            return ToolResult(False, error=err, facts=[f"I can't read metadata for that path: {err}"])
        p = path_guard.resolve(path)
        if not p.exists():
            return ToolResult(False, error="Path does not exist.", facts=[f"{path} does not exist."])
        st = p.stat()
        data = {
            "size_bytes": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "created": datetime.fromtimestamp(st.st_ctime).isoformat(timespec="seconds"),
            "is_dir": p.is_dir(),
        }
        facts = [f"{p}: {'directory' if data['is_dir'] else str(data['size_bytes']) + ' bytes'}, last modified {data['modified']}."]
        return ToolResult(True, data, facts=facts)


class ReadTextFileTool(Tool):
    name = "read_text_file"
    category = PermissionLevel.SAFE
    description = "Read the contents of a small text file (first 50 KB) within the configured indexed roots."
    parameters = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}

    def build_request(self, args):
        req = super().build_request(args)
        req.paths = [args.get("path", "")]
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        path = args["path"]
        err = path_guard.check_readable(path, context.settings)
        if err:
            return ToolResult(False, error=err, facts=[f"I can't read that file: {err}"])
        p = path_guard.resolve(path)
        if not p.is_file():
            return ToolResult(False, error="Not a file.", facts=[f"{path} is not a file."])
        if p.suffix.lower() not in _TEXT_EXTENSIONS and p.name.lower() not in {"readme", "license", "dockerfile"}:
            return ToolResult(False, error="Refusing to read non-text file.", facts=[f"{path} does not look like a text file; refusing to read it."])
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read(50_000)
        except OSError as exc:
            return ToolResult(False, error=str(exc), facts=[f"I could not read {path}: {exc}"])
        return ToolResult(True, {"content": content, "truncated": p.stat().st_size > 50_000}, facts=[f"Read {len(content)} characters from {path}."])


class GetRecentFilesTool(Tool):
    name = "get_recent_files"
    category = PermissionLevel.READ
    description = "List the most recently modified files across the configured indexed roots."
    parameters = {
        "type": "object",
        "properties": {"limit": {"type": "integer", "description": "Max results, default 20."}},
    }

    def execute(self, args, context: ToolContext) -> ToolResult:
        limit = int(args.get("limit") or 20)
        candidates = []
        for root in context.settings.indexed_roots:
            if path_guard.check_readable(root, context.settings):
                continue
            for f in path_guard.walk_bounded(root, context.settings):
                try:
                    candidates.append((f.stat().st_mtime, f))
                except OSError:
                    continue
        candidates.sort(key=lambda t: t[0], reverse=True)
        top = candidates[:limit]
        facts = [f"{len(top)} most recently modified file(s):"]
        facts += [f"  {f} ({datetime.fromtimestamp(mtime).isoformat(timespec='seconds')})" for mtime, f in top]
        return ToolResult(True, {"files": [{"path": str(f), "modified": datetime.fromtimestamp(mtime).isoformat(timespec="seconds")} for mtime, f in top]}, facts=facts)


TOOLS = [
    SearchFilesTool(), SearchFileContentsTool(), ListDirectoryTool(),
    GetFileMetadataTool(), ReadTextFileTool(), GetRecentFilesTool(),
]
