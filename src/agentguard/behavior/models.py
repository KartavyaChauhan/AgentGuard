"""Immutable data models for the deterministic behavior analyzer."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from typing import Any

from agentguard.policy.models import RiskLevel


@dataclass(frozen=True, slots=True)
class BehaviorFinding:
    """An immutable record of a suspicious behavior sequence detected by a rule."""

    finding_id: str
    rule_id: str
    severity: RiskLevel
    title: str
    description: str
    event_ids: tuple[str, ...]
    evidence: dict[str, Any]
    confidence: float

    def __post_init__(self):
        # Validate confidence range
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")

        # Defensively copy evidence dictionary
        if self.evidence is not None:
            object.__setattr__(self, "evidence", copy.deepcopy(self.evidence))
            
    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation suitable for serialization."""
        data = asdict(self)
        # Convert enums and tuples for JSON compatibility
        data["severity"] = self.severity.value
        data["event_ids"] = list(self.event_ids)
        return data
