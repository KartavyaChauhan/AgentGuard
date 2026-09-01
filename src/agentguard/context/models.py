"""Context-aware models for security assessment."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from agentguard.outcome.models import TaskContract
from agentguard.intent.models import TaskIntent


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """An immutable security context representing the execution environment and task constraints."""
    session_id: str
    agent_id: str
    task_contract: TaskContract | None = None
    active_intent: TaskIntent | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Defensively copy metadata dictionary
        if self.metadata is not None:
            object.__setattr__(self, "metadata", copy.deepcopy(self.metadata))
