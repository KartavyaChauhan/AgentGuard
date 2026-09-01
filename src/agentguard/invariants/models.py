"""Immutable models for the security invariant test harness."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from agentguard.policy.models import RiskLevel
from agentguard.events.models import ToolEvent
from agentguard.context.models import SecurityContext


class RuleScope(Enum):
    """The scope at which a security invariant applies."""
    GLOBAL = "global"
    SESSION = "session"
    TASK = "task"


@dataclass(frozen=True, slots=True)
class SecurityInvariant:
    """An immutable definition of a security invariant property."""
    invariant_id: str
    name: str
    description: str
    severity: RiskLevel
    scope: RuleScope = RuleScope.GLOBAL
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class InvariantViolation:
    """An immutable record of a broken security invariant."""
    violation_id: str
    invariant_id: str
    severity: RiskLevel
    description: str
    event_ids: tuple[str, ...]
    evidence: dict[str, Any]

    def __post_init__(self):
        # Defensively copy evidence dictionary
        if self.evidence is not None:
            object.__setattr__(self, "evidence", copy.deepcopy(self.evidence))


@dataclass(frozen=True, slots=True)
class SecurityTestCase:
    """An immutable test case representing a recorded trajectory."""
    test_id: str
    name: str
    description: str
    events: tuple[ToolEvent, ...]
    expected_violations: tuple[str, ...]
    context: Optional[SecurityContext] = None


@dataclass(frozen=True, slots=True)
class SecurityTestResult:
    """An immutable result of evaluating a single test case."""
    test_id: str
    status: str  # "PASS" or "FAIL"
    expected: tuple[str, ...]
    actual: tuple[str, ...]
    explanation: str


@dataclass(frozen=True, slots=True)
class SecurityTestReport:
    """An immutable report summarizing the evaluation of multiple test cases."""
    total_tests: int
    passed: int
    failed: int
    results: tuple[SecurityTestResult, ...]
