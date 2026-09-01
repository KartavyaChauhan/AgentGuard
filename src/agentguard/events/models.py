"""Immutable event models for the session event store."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.models import ExecutionStatus

@dataclass(frozen=True, slots=True)
class ToolEvent:
    """An immutable record of a tool execution attempt."""

    event_id: str
    timestamp: datetime
    session_id: str
    agent_id: str | None
    tool_name: str
    arguments: dict[str, Any]
    policy_action: PolicyAction
    risk_level: RiskLevel
    execution_status: ExecutionStatus
    rule_id: str | None = None
    duration_ms: float | None = None
    data_classifications: tuple[str, ...] = ()
    provenance_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()

    def __post_init__(self):
        # Enforce timezone awareness
        if self.timestamp.tzinfo is None:
            raise ValueError("ToolEvent timestamp must be timezone-aware.")
        
        # Defensively copy mutable dictionaries to ensure immutability
        if self.arguments is not None:
            # Bypass frozen=True to set the copied dictionary
            object.__setattr__(self, "arguments", copy.deepcopy(self.arguments))
