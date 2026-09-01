"""Models for the Realistic Agent Security Benchmark."""

from dataclasses import dataclass, field
from typing import Dict, Any, Tuple, List, Optional
from enum import Enum

from agentguard.context.models import SecurityContext
from agentguard.report.models import SecurityAssessment


class ScenarioExpectedOutcome(str, Enum):
    SAFE = "safe"
    ATTACK = "attack"
    FAILED_EVIDENCE = "failed_evidence"


@dataclass(frozen=True)
class MockToolCall:
    tool_name: str
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BenchmarkScenario:
    scenario_id: str
    description: str
    expected_outcome: ScenarioExpectedOutcome
    calls: Tuple[MockToolCall, ...]
    context: Optional[SecurityContext] = None


@dataclass(frozen=True)
class BenchmarkResult:
    scenario_id: str
    baseline_status: str
    guarded_status: str
    violations: Tuple[str, ...]
    findings: Tuple[str, ...]
    protected: bool
    explanation: str
    risk_score: int = 0
    risk_severity: str = "LOW"
    policy_latency_ms: float = 0.0
    invariant_latency_ms: float = 0.0
    total_latency_ms: float = 0.0


@dataclass(frozen=True)
class BenchmarkReport:
    total_scenarios: int
    protected_scenarios: int
    unprotected_scenarios: int
    detection_rate: float
    false_positive_count: int
    results: Tuple[BenchmarkResult, ...]
    avg_policy_latency_ms: float
    avg_invariant_latency_ms: float
    total_guarded_time_ms: float
    assessment: Optional[SecurityAssessment] = None
