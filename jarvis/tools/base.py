"""Shared tool vocabulary: the schema every tool exposes to the LLM, and the
result shape every tool returns to the orchestrator.

A Tool never decides whether it's allowed to run -- it only describes itself
(build_request) and does the work once the orchestrator tells it the policy
engine already said ALLOW or the user already approved (execute). This keeps
"is this OK" and "how do I do this" in separate places, which is what makes
the policy engine testable in isolation from every tool's implementation.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from jarvis.security.permissions import ActionRequest, PermissionLevel


@dataclass
class ToolResult:
    success: bool
    # Machine-readable payload for the orchestrator/UI.
    data: Any = None
    error: str | None = None
    # Human-readable lines the LLM should quote close to verbatim -- these
    # are the ground truth the "never hallucinate system information" rule
    # depends on. Anything the LLM adds beyond these lines is its own
    # inference and must be phrased as such.
    facts: list[str] = field(default_factory=list)


@dataclass
class ToolContext:
    """Everything a tool's execute() may need, bundled so Tool.execute has a
    single extra argument regardless of what the tool touches."""

    settings: Any
    sandbox: Any = None
    memory: Any = None
    project_index: Any = None


class Tool(ABC):
    name: str = ""
    category: PermissionLevel = PermissionLevel.READ
    description: str = ""
    parameters: dict[str, Any] = {}
    is_command_tool: bool = False

    def build_request(self, args: dict[str, Any]) -> ActionRequest:
        """Default request builder. Tools that touch specific paths or
        commands should override this to populate `paths`/`command`/`cwd`
        so the policy engine can apply deny-root and command checks.
        """
        return ActionRequest(
            tool_name=self.name,
            args=args,
            description=self.describe(args),
        )

    def describe(self, args: dict[str, Any]) -> str:
        return f"{self.name}({', '.join(f'{k}={v!r}' for k, v in args.items())})"

    @abstractmethod
    def execute(self, args: dict[str, Any], context: ToolContext) -> ToolResult: ...

    def llm_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters or {"type": "object", "properties": {}},
            },
        }
