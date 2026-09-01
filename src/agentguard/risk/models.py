"""Immutable data models for deterministic trajectory risk assessment."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class RiskTrend(Enum):
    INCREASING = "INCREASING"
    STABLE = "STABLE"
    DECREASING = "DECREASING"


class RiskSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class RiskContribution:
    """An immutable record of points contributed to a risk score."""
    source_type: str
    source_id: str
    points: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """An immutable record of the total trajectory risk at a point in time."""
    session_id: str
    score: int
    severity: RiskSeverity
    trend: RiskTrend
    contributions: tuple[RiskContribution, ...]
    reasons: tuple[str, ...]

    def __post_init__(self):
        # We ensure contributions and reasons are tuples for immutability
        if not isinstance(self.contributions, tuple):
            object.__setattr__(self, "contributions", tuple(self.contributions))
        if not isinstance(self.reasons, tuple):
            object.__setattr__(self, "reasons", tuple(self.reasons))

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation suitable for serialization."""
        return {
            "session_id": self.session_id,
            "score": self.score,
            "severity": self.severity.value,
            "trend": self.trend.value,
            "contributions": [c.to_dict() for c in self.contributions],
            "reasons": list(self.reasons),
        }
