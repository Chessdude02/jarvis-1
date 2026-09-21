"""Git inspection tools. All read-only (`git status`, `git log`, ...), run
directly with a short timeout rather than through the full Sandbox, since
they never need approval and never write.
"""
from __future__ import annotations

import subprocess

from jarvis.security.permissions import PermissionLevel
from jarvis.tools import path_guard
from jarvis.tools.base import Tool, ToolContext, ToolResult


def _run_git(args: list[str], cwd: str) -> tuple[int, str, str]:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=10)
        return out.returncode, out.stdout, out.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, "", str(exc)


class GetGitStatusTool(Tool):
    name = "get_git_status"
    category = PermissionLevel.READ
    description = "Get git branch, ahead/behind, and uncommitted-change summary for a repository path."
    parameters = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}

    def build_request(self, args):
        req = super().build_request(args)
        req.paths = [args.get("path", "")]
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        path = args["path"]
        err = path_guard.check_readable(path, context.settings)
        if err:
            return ToolResult(False, error=err, facts=[f"I can't inspect that repository: {err}"])

        code, out, err_text = _run_git(["rev-parse", "--is-inside-work-tree"], path)
        if code != 0:
            return ToolResult(True, {"is_git_repo": False}, facts=[f"{path} is not a git repository."])

        _, branch, _ = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], path)
        _, status_out, _ = _run_git(["status", "--porcelain"], path)
        changed = [l for l in status_out.splitlines() if l.strip()]
        _, remote_out, _ = _run_git(["status", "-sb"], path)
        data = {
            "is_git_repo": True,
            "branch": branch.strip(),
            "uncommitted_changes": len(changed),
            "changed_files": changed[:50],
            "status_summary": remote_out.splitlines()[0] if remote_out else "",
        }
        facts = [
            f"Branch: {data['branch']}.",
            f"Uncommitted changes: {data['uncommitted_changes']}.",
        ]
        return ToolResult(True, data, facts=facts)


class InspectGitRepositoryTool(Tool):
    name = "inspect_git_repository"
    category = PermissionLevel.READ
    description = "Get repository metadata: remote URL, current branch, last commit, uncommitted change count."
    parameters = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}

    def build_request(self, args):
        req = super().build_request(args)
        req.paths = [args.get("path", "")]
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        path = args["path"]
        err = path_guard.check_readable(path, context.settings)
        if err:
            return ToolResult(False, error=err, facts=[f"I can't inspect that repository: {err}"])

        code, _, _ = _run_git(["rev-parse", "--is-inside-work-tree"], path)
        if code != 0:
            return ToolResult(True, {"is_git_repo": False}, facts=[f"{path} is not a git repository."])

        _, remote, _ = _run_git(["remote", "get-url", "origin"], path)
        _, branch, _ = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], path)
        _, last_commit, _ = _run_git(["log", "-1", "--pretty=%h %s (%an, %ar)"], path)
        _, status_out, _ = _run_git(["status", "--porcelain"], path)
        changed = [l for l in status_out.splitlines() if l.strip()]

        data = {
            "remote": remote.strip() or None,
            "branch": branch.strip(),
            "last_commit": last_commit.strip() or None,
            "uncommitted_changes": len(changed),
        }
        facts = [
            f"Remote: {data['remote'] or 'none configured'}.",
            f"Branch: {data['branch']}.",
            f"Last commit: {data['last_commit'] or 'no commits yet'}.",
            f"Uncommitted changes: {data['uncommitted_changes']}.",
        ]
        return ToolResult(True, data, facts=facts)


TOOLS = [GetGitStatusTool(), InspectGitRepositoryTool()]
