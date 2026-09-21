"""Development-environment inspection tools. Read-only; run short-lived
subprocesses directly (own timeout) rather than through Sandbox, matching
the git tools -- nothing here ever needs user approval.
"""
from __future__ import annotations

import shutil
import subprocess
import sys

import psutil

from jarvis.security.permissions import PermissionLevel
from jarvis.tools import path_guard
from jarvis.tools.base import Tool, ToolContext, ToolResult

_COMMON_DEV_PORTS = {3000: "React/Node dev server", 5173: "Vite", 8000: "Django/FastAPI",
                      8080: "generic web/proxy", 5000: "Flask", 4200: "Angular",
                      27017: "MongoDB", 5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis"}


def _run(cmd: list[str], timeout: int = 5) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        text = (out.stdout or out.stderr).strip()
        return text.splitlines()[0] if text else None
    except (OSError, subprocess.TimeoutExpired):
        return None


class InspectPythonEnvironmentTool(Tool):
    name = "inspect_python_environment"
    category = PermissionLevel.READ
    description = "Get the active Python version, whether a virtualenv is active, and whether requirements.txt/pyproject.toml exists for a project."
    parameters = {"type": "object", "properties": {"path": {"type": "string", "description": "Project path to check for dependency files."}}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        import os
        data = {
            "python_version": sys.version.split()[0],
            "executable": sys.executable,
            "virtualenv_active": bool(os.environ.get("VIRTUAL_ENV")),
        }
        facts = [f"Python {data['python_version']} at {data['executable']}."]
        facts.append("A virtualenv is active." if data["virtualenv_active"] else "No virtualenv is currently active.")
        path = args.get("path")
        if path and not path_guard.check_readable(path, context.settings):
            p = path_guard.resolve(path)
            data["has_requirements_txt"] = (p / "requirements.txt").exists()
            data["has_pyproject_toml"] = (p / "pyproject.toml").exists()
            data["has_venv_dir"] = (p / ".venv").exists() or (p / "venv").exists()
            facts.append(f"requirements.txt: {'present' if data['has_requirements_txt'] else 'not found'}.")
            facts.append(f"pyproject.toml: {'present' if data['has_pyproject_toml'] else 'not found'}.")
        return ToolResult(True, data, facts=facts)


class InspectNodeEnvironmentTool(Tool):
    name = "inspect_node_environment"
    category = PermissionLevel.READ
    description = "Get node/npm versions and whether package.json exists for a project."
    parameters = {"type": "object", "properties": {"path": {"type": "string"}}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        node_v = _run([shutil.which("node") or "node", "--version"]) if shutil.which("node") else None
        npm_v = _run([shutil.which("npm") or "npm", "--version"]) if shutil.which("npm") else None
        data = {"node_version": node_v, "npm_version": npm_v}
        facts = [f"node: {node_v or 'not found on PATH'}.", f"npm: {npm_v or 'not found on PATH'}."]
        path = args.get("path")
        if path and not path_guard.check_readable(path, context.settings):
            p = path_guard.resolve(path)
            data["has_package_json"] = (p / "package.json").exists()
            facts.append(f"package.json: {'present' if data['has_package_json'] else 'not found'}.")
        return ToolResult(True, data, facts=facts)


class InspectDockerTool(Tool):
    name = "inspect_docker"
    category = PermissionLevel.READ
    description = "Check whether Docker is installed/running and list running containers."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        if not shutil.which("docker"):
            return ToolResult(True, {"installed": False}, facts=["Docker is not installed (or not on PATH)."])
        try:
            out = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"],
                                  capture_output=True, text=True, timeout=8)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ToolResult(True, {"installed": True, "running": False}, facts=[f"Docker is installed but the daemon could not be reached: {exc}"])
        if out.returncode != 0:
            return ToolResult(True, {"installed": True, "running": False}, facts=["Docker is installed but the daemon does not appear to be running."])
        containers = [l for l in out.stdout.splitlines() if l.strip()]
        facts = [f"Docker is running with {len(containers)} container(s) up."] + containers
        return ToolResult(True, {"installed": True, "running": True, "containers": containers}, facts=facts)


class InspectPortsTool(Tool):
    name = "inspect_ports"
    category = PermissionLevel.READ
    description = "List TCP ports currently in LISTEN state on this machine."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        try:
            conns = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError):
            return ToolResult(True, {"ports": []}, facts=["I cannot verify open ports: permission denied reading the connection table."])
        listening = sorted({c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN and c.laddr})
        facts = [f"{len(listening)} port(s) listening: {listening}."]
        return ToolResult(True, {"listening_ports": listening}, facts=facts)


class InspectRunningServersTool(Tool):
    name = "inspect_running_servers"
    category = PermissionLevel.READ
    description = "Identify which common local development servers (React, Vite, Django, Postgres, etc.) appear to be running, based on listening ports."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        try:
            conns = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError):
            return ToolResult(True, {"servers": []}, facts=["I cannot verify running servers: permission denied reading the connection table."])
        listening = {c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN and c.laddr}
        matches = [{"port": p, "likely": _COMMON_DEV_PORTS[p]} for p in sorted(listening) if p in _COMMON_DEV_PORTS]
        facts = [f"Port {m['port']}: likely {m['likely']}." for m in matches] or ["No common development-server ports were found listening."]
        return ToolResult(True, {"servers": matches}, facts=facts)


TOOLS = [
    InspectPythonEnvironmentTool(), InspectNodeEnvironmentTool(), InspectDockerTool(),
    InspectPortsTool(), InspectRunningServersTool(),
]
