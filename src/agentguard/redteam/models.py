"""Red-team benchmark models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from agentguard.policy.models import PolicyAction
from agentguard.trust.models import TrustDecision


@dataclass(frozen=True)
class AttackCall:
    """A tool call in an attack trajectory."""
    tool_name: str
    arguments: dict


@dataclass(frozen=True)
class AttackScenario:
    """Immutable model representing a red-team scenario."""
    attack_id: str
    name: str
    description: str
    severity: str
    trajectory: tuple[AttackCall, ...]
    expected_security_property: str
    category: str


@dataclass(frozen=True)
class AttackResult:
    """Immutable model representing the outcome of an attack scenario passing through AgentGuard."""
    attack_id: str
    classification: Literal["BLOCKED", "DETECTED", "MISSED", "SAFE", "FALSE_POSITIVE"]
    trust_decision: str
    risk_score: int
    risk_severity: str
    policy_actions: tuple[str, ...]
    behavioral_findings: tuple[str, ...]
    invariant_violations: tuple[str, ...]
    upstream_side_effects: int
    event_ids: tuple[str, ...]
    duration_ms: float
    data_flow_findings: tuple[str, ...] = ()
    response_findings: tuple[str, ...] = ()
    tool_poisoning_findings: tuple[str, ...] = ()
