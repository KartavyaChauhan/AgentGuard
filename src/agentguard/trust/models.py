"""Immutable models for the Trust Engine."""

from __future__ import annotations
import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Tuple


class TrustDecision(Enum):
    """The final trust assessment decision for a trajectory."""
    TRUSTED = "TRUSTED"
    BLOCKED = "BLOCKED"
    UNVERIFIED = "UNVERIFIED"
    RISKY = "RISKY"
    ERROR = "ERROR"


@dataclass(frozen=True)
class TrustAssessment:
    """A deterministic, unified trust assessment for an agent session/task."""
    
    decision: TrustDecision
    session_id: str
    agent_id: str
    task_contract_id: str | None
    
    # Normalized signals
    risk_score: int
    risk_severity: str
    policy_status: str
    behavior_status: str
    invariant_status: str
    outcome_status: str
    
    # Evidence & Explanations (defensively copied, no raw tool output)
    confidence: float
    reasons: Tuple[str, ...]
    evidence: dict[str, bool]
    findings: Tuple[str, ...]
    violations: Tuple[str, ...]
    
    generated_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    def __post_init__(self):
        """Defensively copy any dict structures to ensure immutability."""
        # Because it's frozen, we must use object.__setattr__
        object.__setattr__(
            self,
            "evidence",
            {k: bool(v) for k, v in self.evidence.items()}
        )
