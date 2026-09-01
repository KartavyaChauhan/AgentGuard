"""Execution result models.

Immutable data models for tool execution outcomes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from agentguard.policy.models import PolicyDecision


class ExecutionStatus(Enum):
    """Outcome of a tool execution attempt."""

    EXECUTED = "EXECUTED"
    DENIED = "DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Immutable result of a :class:`~agentguard.execution.executor.ToolExecutor` call.

    Parameters
    ----------
    status:
        What happened — executed, denied, needs approval, or failed.
    decision:
        The :class:`PolicyDecision` that governed the outcome.
    output:
        Return value of the tool, if it was executed successfully.
    error:
        Human-readable error message if something went wrong.
        Never contains raw Python stack traces.
    duration_ms:
        Wall-clock time in milliseconds for the tool invocation.
        ``None`` when the tool was never invoked (DENIED, APPROVAL_REQUIRED)
        or when timing is not applicable.
    """

    status: ExecutionStatus
    decision: PolicyDecision
    output: Any = None
    error: str | None = None
    duration_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation suitable for serialization."""
        data = asdict(self)
        data["status"] = self.status.value
        data["decision"] = self.decision.to_dict()
        return data
