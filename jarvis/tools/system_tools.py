"""READ-category tools: facts about the machine itself. Every tool here is
always ALLOW at the policy layer -- nothing here writes anything.
"""
from __future__ import annotations

import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime

import psutil

from jarvis.security.permissions import PermissionLevel
from jarvis.tools.base import Tool, ToolContext, ToolResult


class GetSystemInfoTool(Tool):
    name = "get_system_info"
    category = PermissionLevel.READ
    description = "Get OS, hostname, Python version, and system uptime."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        boot = psutil.boot_time()
        uptime_s = time.time() - boot
        data = {
            "os": f"{platform.system()} {platform.release()}",
            "os_version": platform.version(),
            "hostname": socket.gethostname(),
            "python_version": sys.version.split()[0],
            "uptime_hours": round(uptime_s / 3600, 1),
            "boot_time": datetime.fromtimestamp(boot).isoformat(timespec="seconds"),
        }
        facts = [
            f"OS: {data['os']}",
            f"Hostname: {data['hostname']}",
            f"Python (running JARVIS): {data['python_version']}",
            f"System has been up for {data['uptime_hours']} hours (since {data['boot_time']}).",
        ]
        return ToolResult(True, data, facts=facts)


class GetCpuUsageTool(Tool):
    name = "get_cpu_usage"
    category = PermissionLevel.READ
    description = "Get current CPU utilization, per-core, and the top processes by CPU."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        overall = psutil.cpu_percent(interval=0.3)
        per_core = psutil.cpu_percent(interval=0.0, percpu=True)
        procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent"]):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        top = sorted(procs, key=lambda p: p.get("cpu_percent") or 0, reverse=True)[:5]
        data = {"overall_percent": overall, "per_core_percent": per_core, "top_processes": top}
        facts = [f"Overall CPU usage: {overall}%."]
        facts += [f"  {p['name']} (pid {p['pid']}): {p.get('cpu_percent', 0)}%" for p in top]
        return ToolResult(True, data, facts=facts)


class GetMemoryUsageTool(Tool):
    name = "get_memory_usage"
    category = PermissionLevel.READ
    description = "Get RAM usage: total, used, available, and percent."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        vm = psutil.virtual_memory()
        data = {
            "total_gb": round(vm.total / 2**30, 2),
            "used_gb": round(vm.used / 2**30, 2),
            "available_gb": round(vm.available / 2**30, 2),
            "percent": vm.percent,
        }
        facts = [f"RAM: {data['used_gb']} GB used of {data['total_gb']} GB ({data['percent']}%)."]
        return ToolResult(True, data, facts=facts)


class GetDiskUsageTool(Tool):
    name = "get_disk_usage"
    category = PermissionLevel.READ
    description = "Get disk usage per mounted drive/partition."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        parts = []
        facts = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            entry = {
                "device": part.device,
                "mountpoint": part.mountpoint,
                "total_gb": round(usage.total / 2**30, 2),
                "used_gb": round(usage.used / 2**30, 2),
                "free_gb": round(usage.free / 2**30, 2),
                "percent": usage.percent,
            }
            parts.append(entry)
            facts.append(f"{part.device} ({part.mountpoint}): {entry['free_gb']} GB free of {entry['total_gb']} GB ({entry['percent']}% used).")
        return ToolResult(True, {"drives": parts}, facts=facts)


class GetGpuInfoTool(Tool):
    name = "get_gpu_info"
    category = PermissionLevel.READ
    description = "Get GPU model and utilization if detectable (NVIDIA via nvidia-smi)."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        nvidia_smi = shutil.which("nvidia-smi")
        if not nvidia_smi:
            return ToolResult(
                True, {"gpus": []},
                facts=["I cannot verify GPU information: nvidia-smi was not found on this system."],
            )
        try:
            out = subprocess.run(
                [nvidia_smi, "--query-gpu=name,memory.total,memory.used,utilization.gpu",
                 "--format=csv,noheader"],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ToolResult(False, error=str(exc), facts=[f"I could not query the GPU: {exc}"])
        if out.returncode != 0:
            return ToolResult(True, {"gpus": []}, facts=["I cannot verify GPU information: nvidia-smi returned an error."])
        gpus = [line.strip() for line in out.stdout.splitlines() if line.strip()]
        return ToolResult(True, {"gpus": gpus}, facts=[f"GPU: {g}" for g in gpus] or ["No NVIDIA GPU reported."])


class GetBatteryStatusTool(Tool):
    name = "get_battery_status"
    category = PermissionLevel.READ
    description = "Get battery percentage and charging status, if this machine has a battery."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        battery = psutil.sensors_battery()
        if battery is None:
            return ToolResult(True, {"present": False}, facts=["I cannot verify battery status: no battery was detected on this system."])
        data = {"present": True, "percent": battery.percent, "plugged_in": battery.power_plugged}
        state = "charging" if battery.power_plugged else "on battery"
        return ToolResult(True, data, facts=[f"Battery: {battery.percent}% ({state})."])


class GetNetworkStatusTool(Tool):
    name = "get_network_status"
    category = PermissionLevel.READ
    description = "Get network interfaces and whether they are up."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        interfaces = []
        for name, st in stats.items():
            ips = [a.address for a in addrs.get(name, []) if a.family == socket.AF_INET]
            interfaces.append({"name": name, "up": st.isup, "speed_mbps": st.speed, "ipv4": ips})
        facts = [f"{i['name']}: {'up' if i['up'] else 'down'}" + (f", {i['ipv4'][0]}" if i["ipv4"] else "") for i in interfaces]
        return ToolResult(True, {"interfaces": interfaces}, facts=facts)


class GetRunningProcessesTool(Tool):
    name = "get_running_processes"
    category = PermissionLevel.READ
    description = "List currently running processes, optionally filtered by name substring."
    parameters = {
        "type": "object",
        "properties": {"name_filter": {"type": "string", "description": "Optional case-insensitive substring to filter process names."}},
    }

    def execute(self, args, context: ToolContext) -> ToolResult:
        name_filter = (args.get("name_filter") or "").lower()
        procs = []
        for p in psutil.process_iter(["pid", "name", "memory_percent", "cpu_percent"]):
            try:
                info = p.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if name_filter and name_filter not in (info.get("name") or "").lower():
                continue
            procs.append(info)
        procs = sorted(procs, key=lambda p: p.get("memory_percent") or 0, reverse=True)[:50]
        facts = [f"{len(procs)} process(es) matched." if name_filter else f"{len(procs)} processes shown (top 50 by memory)."]
        return ToolResult(True, {"processes": procs}, facts=facts)


class GetInstalledSoftwareTool(Tool):
    name = "get_installed_software"
    category = PermissionLevel.READ
    description = "List installed software (Windows registry-based). Returns an explicit 'cannot verify' on unsupported platforms."
    parameters = {
        "type": "object",
        "properties": {"name_filter": {"type": "string", "description": "Optional case-insensitive substring, e.g. 'postgres' or 'java'."}},
    }

    def execute(self, args, context: ToolContext) -> ToolResult:
        if sys.platform != "win32":
            return ToolResult(True, {"software": []}, facts=["I cannot verify installed software: this only reads the Windows registry, and JARVIS is not running on Windows here."])
        try:
            import winreg
        except ImportError:
            return ToolResult(True, {"software": []}, facts=["I cannot verify installed software: winreg is unavailable."])

        name_filter = (args.get("name_filter") or "").lower()
        found: list[str] = []
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hive, path in roots:
            try:
                key = winreg.OpenKey(hive, path)
            except OSError:
                continue
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                    display_name = winreg.QueryValueEx(sub, "DisplayName")[0]
                except OSError:
                    continue
                if not name_filter or name_filter in display_name.lower():
                    found.append(display_name)
        found = sorted(set(found))
        facts = [f"{len(found)} matching installed program(s) found."] if name_filter else [f"{len(found)} installed programs found."]
        return ToolResult(True, {"software": found}, facts=facts)


class GetEnvironmentInfoTool(Tool):
    name = "get_environment_info"
    category = PermissionLevel.READ
    description = "Get the current working directory, PATH entries, and key tool versions (Python, pip, git, node, docker, java)."
    parameters = {"type": "object", "properties": {}}

    def execute(self, args, context: ToolContext) -> ToolResult:
        import os

        def version_of(exe: str, flag: str = "--version") -> str | None:
            path = shutil.which(exe)
            if not path:
                return None
            try:
                out = subprocess.run([exe, flag], capture_output=True, text=True, timeout=5)
                return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else None
            except (OSError, subprocess.TimeoutExpired):
                return None

        versions = {
            "python": version_of(sys.executable, "--version"),
            "pip": version_of("pip"),
            "git": version_of("git"),
            "node": version_of("node"),
            "docker": version_of("docker"),
            "java": version_of("java", "-version"),
        }
        data = {
            "cwd": os.getcwd(),
            "path_entries": os.environ.get("PATH", "").split(os.pathsep),
            "versions": versions,
        }
        facts = [f"Current working directory: {data['cwd']}."]
        for tool, v in versions.items():
            facts.append(f"{tool}: {v if v else 'not found on PATH'}.")
        return ToolResult(True, data, facts=facts)


TOOLS = [
    GetSystemInfoTool(), GetCpuUsageTool(), GetMemoryUsageTool(), GetDiskUsageTool(),
    GetGpuInfoTool(), GetBatteryStatusTool(), GetNetworkStatusTool(),
    GetRunningProcessesTool(), GetInstalledSoftwareTool(), GetEnvironmentInfoTool(),
]
