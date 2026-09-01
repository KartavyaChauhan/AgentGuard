"""Security assessment reporting models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from agentguard.invariants.models import InvariantViolation
from agentguard.policy.models import RiskLevel


@dataclass(frozen=True, slots=True)
class SecurityAssessment:
    """An immutable deterministic security report."""
    score: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    violations: Tuple[InvariantViolation, ...]
    false_positive_count: int
    tested_scenarios: int
    protected_scenarios: int
    missed_scenarios: int

    @classmethod
    def calculate(
        cls,
        violations: Tuple[InvariantViolation, ...],
        false_positive_count: int,
        tested_scenarios: int,
        protected_scenarios: int,
        missed_scenarios: int,
    ) -> SecurityAssessment:
        critical = 0
        high = 0
        medium = 0
        low = 0

        for v in violations:
            if v.severity == RiskLevel.CRITICAL:
                critical += 1
            elif v.severity == RiskLevel.HIGH:
                high += 1
            elif v.severity == RiskLevel.MEDIUM:
                medium += 1
            elif v.severity == RiskLevel.LOW:
                low += 1

        # Heuristic security score calculation
        score = 100
        score -= critical * 30
        score -= high * 15
        score -= medium * 7
        score -= low * 2
        
        # Additional penalty for missed scenarios
        score -= missed_scenarios * 30

        # Clamp to [0, 100]
        score = max(0, min(100, score))

        return cls(
            score=score,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            violations=tuple(violations),
            false_positive_count=false_positive_count,
            tested_scenarios=tested_scenarios,
            protected_scenarios=protected_scenarios,
            missed_scenarios=missed_scenarios,
        )
