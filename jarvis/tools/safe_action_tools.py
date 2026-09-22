"""SAFE-category actions: things that touch the OS shell but don't modify
user data -- opening a file/folder/app in its default handler, opening a
terminal window, copying text to the clipboard. Per the spec these are
"usually allowed automatically", so category=SAFE (policy engine -> ALLOW),
but they are still scoped to indexed roots where a path is involved.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

from jarvis.security.permissions import PermissionLevel
from jarvis.tools import path_guard
from jarvis.tools.base import Tool, ToolContext, ToolResult


class OpenFileTool(Tool):
    name = "open_file"
    category = PermissionLevel.SAFE
    description = "Open a file with its default OS application."
    parameters = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}

    def build_request(self, args):
        req = super().build_request(args)
        req.paths = [args.get("path", "")]
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        path = args["path"]
        err = path_guard.check_readable(path, context.settings)
        if err:
            return ToolResult(False, error=err, facts=[f"I can't open that file: {err}"])
        p = path_guard.resolve(path)
        if not p.exists():
            return ToolResult(False, error="File does not exist.", facts=[f"{path} does not exist."])
        try:
            if sys.platform == "win32":
                os.startfile(str(p))  # noqa: S606 -- scoped to indexed roots above
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
        except OSError as exc:
            return ToolResult(False, error=str(exc), facts=[f"I could not open {path}: {exc}"])
        return ToolResult(True, {"opened": str(p)}, facts=[f"Opened {p} with the default application."])


class OpenFolderTool(Tool):
    name = "open_folder"
    category = PermissionLevel.SAFE
    description = "Open a folder in the OS file explorer."
    parameters = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}

    def build_request(self, args):
        req = super().build_request(args)
        req.paths = [args.get("path", "")]
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        path = args["path"]
        err = path_guard.check_readable(path, context.settings)
        if err:
            return ToolResult(False, error=err, facts=[f"I can't open that folder: {err}"])
        p = path_guard.resolve(path)
        if not p.is_dir():
            return ToolResult(False, error="Not a directory.", facts=[f"{path} is not a directory."])
        try:
            if sys.platform == "win32":
                os.startfile(str(p))  # noqa: S606
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
        except OSError as exc:
            return ToolResult(False, error=str(exc), facts=[f"I could not open {path}: {exc}"])
        return ToolResult(True, {"opened": str(p)}, facts=[f"Opened {p} in the file explorer."])


class OpenApplicationTool(Tool):
    name = "open_application"
    category = PermissionLevel.SAFE
    description = "Launch an application by name (must already be resolvable on PATH, e.g. 'code', 'notepad')."
    parameters = {"type": "object", "properties": {"app_name": {"type": "string"}}, "required": ["app_name"]}

    def build_request(self, args):
        # Found by testing: without this override, the base build_request()
        # (see Tool.build_request's own docstring warning) leaves both
        # request.command and request.paths empty for this tool, which means
        # NOTHING here is visible to the policy engine's deny-list checks --
        # SAFE auto-allows unconditionally, with no path or command for
        # step 1c/1d to inspect. Confirmed against the real PolicyEngine:
        # app_name="nmap"/"hydra"/"mimikatz"/"netcat" all evaluated to ALLOW.
        # shutil.which() resolves an absolute/relative path directly (not
        # just a bare PATH lookup), so app_name could also point at an
        # arbitrary executable already on disk -- e.g. one execute_command
        # was separately approved to write earlier in the same session,
        # letting this tool run it a second time with zero further scrutiny.
        #
        # Setting request.command runs app_name through the same
        # ATTACK_TOOL_PATTERNS / DENY_COMMAND_PATTERNS check execute_command
        # gets (step 1d in policy_engine._evaluate, which runs independently
        # of is_command_tool/category resolution) -- an outright DENY for a
        # known attack tool or security-control name, while an ordinary app
        # ("notepad", "code", "chrome") still resolves to this tool's SAFE
        # base_category as before, since is_command_tool stays False and
        # classify_command() is never invoked. Setting request.paths to the
        # resolved location (when shutil.which succeeds) additionally runs
        # it through the credential/system-root path checks (step 1c).
        req = super().build_request(args)
        app_name = args.get("app_name", "")
        req.command = app_name if isinstance(app_name, str) and app_name else None
        if req.command:
            resolved = shutil.which(req.command)
            if resolved:
                req.paths = [resolved]
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        app_name = args["app_name"]
        resolved = shutil.which(app_name)
        if not resolved:
            return ToolResult(False, error="Application not found on PATH.", facts=[f"I could not find '{app_name}' on PATH; it may not be installed."])
        try:
            subprocess.Popen([resolved])
        except OSError as exc:
            return ToolResult(False, error=str(exc), facts=[f"I could not launch {app_name}: {exc}"])
        return ToolResult(True, {"launched": resolved}, facts=[f"Launched {resolved}."])


class OpenTerminalTool(Tool):
    name = "open_terminal"
    category = PermissionLevel.SAFE
    description = "Open a terminal window at a given directory (does not run any command in it)."
    parameters = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}

    def build_request(self, args):
        req = super().build_request(args)
        req.paths = [args.get("path", "")]
        return req

    def execute(self, args, context: ToolContext) -> ToolResult:
        path = args["path"]
        err = path_guard.check_readable(path, context.settings)
        if err:
            return ToolResult(False, error=err, facts=[f"I can't open a terminal there: {err}"])
        p = path_guard.resolve(path)
        try:
            if sys.platform == "win32":
                subprocess.Popen(["cmd.exe", "/k", f"cd /d {p}"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-a", "Terminal", str(p)])
            else:
                subprocess.Popen(["x-terminal-emulator", "--working-directory", str(p)])
        except OSError as exc:
            return ToolResult(False, error=str(exc), facts=[f"I could not open a terminal: {exc}"])
        return ToolResult(True, {"opened_at": str(p)}, facts=[f"Opened a terminal at {p}. No command was run in it."])


class CopyToClipboardTool(Tool):
    name = "copy_to_clipboard"
    category = PermissionLevel.SAFE
    description = "Copy a short piece of text to the system clipboard."
    parameters = {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}

    def execute(self, args, context: ToolContext) -> ToolResult:
        text = args["text"]
        if sys.platform == "win32":
            try:
                subprocess.run(["clip"], input=text, text=True, check=True, timeout=5)
                return ToolResult(True, {"copied_chars": len(text)}, facts=[f"Copied {len(text)} characters to the clipboard."])
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                return ToolResult(False, error=str(exc), facts=[f"I could not copy to the clipboard: {exc}"])
        return ToolResult(False, error="Clipboard access is only implemented for Windows in this build.",
                           facts=["I cannot verify clipboard access on this platform; clipboard support is Windows-only in this build."])


TOOLS = [OpenFileTool(), OpenFolderTool(), OpenApplicationTool(), OpenTerminalTool(), CopyToClipboardTool()]
