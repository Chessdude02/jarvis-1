"""Builds the small grounding block appended to the system prompt each turn:
just enough live state (time, project count, pending approvals) that the
model doesn't have to guess it or call a tool for obviously-cheap facts.
This is NOT a substitute for tool calls on anything the user actually asked
about -- it exists only to reduce redundant "what time is it" round trips.
"""
from __future__ import annotations

from datetime import datetime


def build_context(settings, project_index: list | None, sandbox) -> dict:
    return {
        "local_time": datetime.now().isoformat(timespec="seconds"),
        "indexed_roots": settings.indexed_roots,
        "indexed_project_count": len(project_index) if project_index else 0,
        "active_commands_running": sandbox.active_count if sandbox else 0,
        "network_online_features_enabled": settings.online_features_enabled,
    }
