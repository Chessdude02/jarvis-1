"""Turns a batch of proposed tool calls into a plan the user sees BEFORE
anything but the read-only steps run. Deliberately deterministic (no LLM
call) -- it just groups already-evaluated policy decisions, so the plan the
user reads is guaranteed to match what the policy engine will actually do,
not a paraphrase of it.
"""
from __future__ import annotations

from dataclasses import dataclass

from jarvis.security.permissions import ActionRequest, Decision, PolicyDecision


@dataclass
class PlanStep:
    index: int
    request: ActionRequest
    decision: PolicyDecision


@dataclass
class Plan:
    steps: list[PlanStep]

    @property
    def read_only_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.decision.decision == Decision.ALLOW]

    @property
    def gated_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.decision.decision == Decision.CONFIRM]

    @property
    def denied_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.decision.decision == Decision.DENY]

    def render(self) -> str:
        lines = ["PLAN"]
        for step in self.steps:
            tag = {
                Decision.ALLOW: "read-only",
                Decision.CONFIRM: f"requires approval ({step.decision.category.value})",
                Decision.DENY: "DENIED",
            }[step.decision.decision]
            lines.append(f"{step.index}. {step.request.description or step.request.tool_name}  [{tag}]")
        if self.gated_steps:
            lines.append("")
            lines.append(f"Steps {', '.join(str(s.index) for s in self.gated_steps)} modify the system and require approval.")
        if self.denied_steps:
            lines.append(f"Steps {', '.join(str(s.index) for s in self.denied_steps)} are not permitted and will be skipped.")
        return "\n".join(lines)


def build_plan(items: list[tuple[ActionRequest, PolicyDecision]]) -> Plan:
    return Plan([PlanStep(i + 1, req, dec) for i, (req, dec) in enumerate(items)])
