"""Central place that knows every tool JARVIS can call.

Building the policy engine's tool_registry (name -> ToolSpec) from the same
source as the LLM's function-calling schema guarantees the two never drift
apart -- a tool the LLM can see is always a tool the policy engine has a
category for.
"""
from __future__ import annotations

from jarvis.security.policy_engine import ToolSpec
from jarvis.tools.base import Tool


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Duplicate tool registration: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def llm_schemas(self) -> list[dict]:
        return [t.llm_schema() for t in self._tools.values()]

    def policy_specs(self) -> dict[str, ToolSpec]:
        return {
            t.name: ToolSpec(name=t.name, base_category=t.category, is_command_tool=t.is_command_tool)
            for t in self._tools.values()
        }


def build_default_registry() -> ToolRegistry:
    from jarvis.tools import (
        dev_tools,
        filesystem_tools,
        git_tools,
        project_tools,
        safe_action_tools,
        system_tools,
        terminal_tools,
    )

    registry = ToolRegistry()
    for module in (
        system_tools,
        filesystem_tools,
        project_tools,
        git_tools,
        safe_action_tools,
        dev_tools,
        terminal_tools,
    ):
        for tool in module.TOOLS:
            registry.register(tool)
    return registry
