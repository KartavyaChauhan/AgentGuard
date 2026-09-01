"""Immutable models for the external evaluation framework."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ExpectedOutcome(str, Enum):
    BLOCKED = "BLOCKED"
    DETECTED = "DETECTED"
    ALLOWED = "ALLOWED"
    SAFE = "SAFE"


class ActualOutcome(str, Enum):
    BLOCKED = "BLOCKED"
    DETECTED = "DETECTED"
    MISSED = "MISSED"
    SAFE = "SAFE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class EvaluationCall:
    """Represents a single tool call in a trajectory."""
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvaluationScenario:
    """An immutable scenario representing an external benchmark item."""
    scenario_id: str
    name: str
    description: str
    category: str
    technique: str
    expected_outcome: ExpectedOutcome
    trajectory: tuple[EvaluationCall, ...]
    task_contract: Optional[dict[str, Any]] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Outcome of a single scenario execution."""
    scenario_id: str
    expected_outcome: ExpectedOutcome
    actual_outcome: ActualOutcome
    violations: tuple[str, ...]
    findings: tuple[str, ...]
    explanation: str
    risk_score: int
    risk_severity: str
    execution_time_ms: float
    policy_time_ms: float
    analysis_time_ms: float
    trust_decision: str | None = None


@dataclass(frozen=True, slots=True)
class EvaluationScore:
    """Aggregate scoring metrics."""
    total: int
    blocked: int
    detected: int
    missed: int
    safe: int
    false_positives: int
    errors: int
    detection_rate: float
    false_positive_rate: float
    miss_rate: float
    error_rate: float
    avg_execution_time_ms: float
    avg_policy_time_ms: float
    avg_analysis_time_ms: float
    avg_attack_risk: float
    avg_safe_risk: float
    
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    category_breakdown: dict[str, dict[str, int]] = field(default_factory=dict)
