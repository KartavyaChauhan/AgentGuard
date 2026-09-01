"""Immutable data models for the policy engine.

All models use ``frozen=True`` dataclasses for immutability and ``slots=True``
for memory efficiency.  They are plain data — no business logic lives here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PolicyAction(Enum):
    """The three possible outcomes of a policy evaluation."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class RiskLevel(Enum):
    """Risk classification for a policy decision."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolRequest:
    """A normalized, immutable description of a tool call to be evaluated.

    Parameters
    ----------
    tool_name:
        Name of the tool being invoked (e.g. ``"read_file"``).
    arguments:
        Keyword arguments passed to the tool.
    agent_id:
        Optional identifier of the agent making the call.
    session_id:
        Optional session identifier for the current interaction.
    """

    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    agent_id: str | None = None
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation suitable for serialization."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The result of evaluating a :class:`ToolRequest` against the policy engine.

    Parameters
    ----------
    action:
        Whether the call is allowed, denied, or requires approval.
    reason:
        Human-readable explanation of the decision.
    rule_id:
        Identifier of the rule that produced this decision, or ``None``
        if no rule matched (default allow).
    risk_level:
        Assessed risk level of the tool call.
    """

    action: PolicyAction
    reason: str
    rule_id: str | None = None
    risk_level: RiskLevel = RiskLevel.LOW

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation suitable for serialization."""
        data = asdict(self)
        # Convert enums to their string values for JSON compatibility.
        data["action"] = self.action.value
        data["risk_level"] = self.risk_level.value
        return data
