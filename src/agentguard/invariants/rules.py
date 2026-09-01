"""Deterministic security invariant rules."""

from __future__ import annotations

import abc
import uuid
from typing import Sequence

from agentguard.events.models import ToolEvent
from agentguard.execution.models import ExecutionStatus
from agentguard.policy.models import RiskLevel, PolicyAction
from agentguard.invariants.models import SecurityInvariant, InvariantViolation, RuleScope
from agentguard.outcome.models import TaskContract
from agentguard.outcome.evaluator import EvidenceEvaluator
from agentguard.context.models import SecurityContext


class SecurityInvariantRule(abc.ABC):
    """Abstract base class for a security invariant."""

    @property
    @abc.abstractmethod
    def invariant(self) -> SecurityInvariant:
        """The invariant definition."""
        pass

    @abc.abstractmethod
    def evaluate(self, events: Sequence[ToolEvent], context: SecurityContext | None = None) -> Sequence[InvariantViolation]:
        """Evaluate the invariant across the full trajectory."""
        pass

    def _create_violation(
        self,
        description: str,
        event_ids: tuple[str, ...],
        evidence: dict,
        severity: RiskLevel | None = None,
    ) -> InvariantViolation:
        return InvariantViolation(
            violation_id=uuid.uuid4().hex,
            invariant_id=self.invariant.invariant_id,
            severity=severity or self.invariant.severity,
            description=description,
            event_ids=event_ids,
            evidence=evidence,
        )


class NoSensitiveDataExfiltrationRule(SecurityInvariantRule):
    """Invariant 1: No Sensitive Data Exfiltration."""

    def __init__(self) -> None:
        self._invariant = SecurityInvariant(
            invariant_id="no-secret-exfiltration",
            name="No Sensitive Data Exfiltration",
            description="Sensitive data must not flow to an external network operation.",
            severity=RiskLevel.CRITICAL,
            scope=RuleScope.SESSION,
        )
        self.sensitive_indicators = {
            ".env", "credentials", "secret", "private_key", "api_key", "token"
        }
        self.network_indicators = {
            "http_request", "network_request", "send_http_request", "upload", "webhook"
        }

    @property
    def invariant(self) -> SecurityInvariant:
        return self._invariant

    def _is_sensitive(self, event: ToolEvent) -> str | None:
        for indicator in self.sensitive_indicators:
            for k, v in event.arguments.items():
                if indicator in str(k).lower() or indicator in str(v).lower():
                    return indicator
        return None

    def evaluate(self, events: Sequence[ToolEvent], context: SecurityContext | None = None) -> Sequence[InvariantViolation]:
        violations = []
        sensitive_event = None
        sensitive_indicator = None

        for event in events:
            if event.execution_status == ExecutionStatus.DENIED:
                continue

            if not sensitive_event:
                indicator = self._is_sensitive(event)
                if indicator:
                    sensitive_event = event
                    sensitive_indicator = indicator
            else:
                if event.tool_name in self.network_indicators:
                    violations.append(
                        self._create_violation(
                            description="Sensitive read followed by network operation.",
                            event_ids=(sensitive_event.event_id, event.event_id),
                            evidence={
                                "source_event": sensitive_event.tool_name,
                                "destination_event": event.tool_name,
                                "matched_indicator": sensitive_indicator,
                            }
                        )
                    )
                    # Reset to find multiple potential violations in a long trajectory
                    sensitive_event = None
                    sensitive_indicator = None

        return violations


class NoUnauthorizedPrivilegeEscalationRule(SecurityInvariantRule):
    """Invariant 2: No Unauthorized Privilege Escalation."""

    def __init__(self) -> None:
        self._invariant = SecurityInvariant(
            invariant_id="privilege-escalation",
            name="No Unauthorized Privilege Escalation",
            description="A session must not transition into privileged operations unless explicit approval evidence exists.",
            severity=RiskLevel.HIGH,
            scope=RuleScope.SESSION,
        )
        self.privileged_indicators = {
            "sudo", "root", "admin", "chmod", "permission_change", "execute_as_admin"
        }

    @property
    def invariant(self) -> SecurityInvariant:
        return self._invariant

    def _is_privileged(self, tool_name: str) -> bool:
        return any(ind in tool_name.lower() for ind in self.privileged_indicators)

    def evaluate(self, events: Sequence[ToolEvent], context: SecurityContext | None = None) -> Sequence[InvariantViolation]:
        violations = []
        has_approval_evidence = any(
            e.policy_action == PolicyAction.REQUIRE_APPROVAL and e.execution_status == ExecutionStatus.EXECUTED
            for e in events
        )

        normal_event = None

        for event in events:
            if event.execution_status == ExecutionStatus.DENIED:
                continue

            if self._is_privileged(event.tool_name):
                if normal_event and not has_approval_evidence:
                    violations.append(
                        self._create_violation(
                            severity=RiskLevel.CRITICAL,
                            description="Unapproved transition to privileged operation.",
                            event_ids=(normal_event.event_id, event.event_id),
                            evidence={
                                "normal_tool": normal_event.tool_name,
                                "privileged_tool": event.tool_name,
                            }
                        )
                    )
                    normal_event = None
            else:
                normal_event = event

        return violations


class RequiredEvidenceRule(SecurityInvariantRule):
    """Invariant 3: Required Evidence Before Completion."""

    def __init__(self, contract: TaskContract | None = None) -> None:
        self.contract = contract
        self._invariant = SecurityInvariant(
            invariant_id="required-test-evidence",
            name="Required Evidence Before Completion",
            description="A task must not be considered satisfied unless all required TaskContract evidence exists.",
            severity=RiskLevel.HIGH,
            scope=RuleScope.TASK,
        )
        self.evaluator = EvidenceEvaluator()

    @property
    def invariant(self) -> SecurityInvariant:
        return self._invariant

    def evaluate(self, events: Sequence[ToolEvent], context: SecurityContext | None = None) -> Sequence[InvariantViolation]:
        # 1. Check whether context.task_contract exists
        active_contract = None
        if context is not None:
            active_contract = getattr(context, "task_contract", None)
        else:
            active_contract = self.contract
            
        # 2. If no contract exists: return no violations
        if not active_contract:
            return []
            
        # 3. If a contract exists: evaluate it
        assessment = self.evaluator.evaluate(active_contract, events)
        if not assessment.satisfied:
            return [
                self._create_violation(
                    description=assessment.explanation,
                    event_ids=assessment.evidence_ids,
                    evidence={
                        "missing": list(assessment.missing_evidence),
                        "failed": list(assessment.failed_evidence),
                    }
                )
            ]
        return []


class NoSuspiciousChainRule(SecurityInvariantRule):
    """Invariant 4: No Suspicious Chain."""

    def __init__(self) -> None:
        self._invariant = SecurityInvariant(
            invariant_id="suspicious-chain",
            name="No Suspicious Chain",
            description="Known dangerous sequences must never occur.",
            severity=RiskLevel.CRITICAL,
            scope=RuleScope.SESSION,
        )
        self.sequence = ["read_file", "shell", "request"]

    @property
    def invariant(self) -> SecurityInvariant:
        return self._invariant

    def evaluate(self, events: Sequence[ToolEvent], context: SecurityContext | None = None) -> Sequence[InvariantViolation]:
        violations = []
        state_idx = 0
        chain_events = []

        for event in events:
            if event.execution_status == ExecutionStatus.DENIED:
                continue

            if self.sequence[state_idx] in event.tool_name:
                chain_events.append(event)
                state_idx += 1
                
                if state_idx == len(self.sequence):
                    violations.append(
                        self._create_violation(
                            description=f"Suspicious chain detected: {' -> '.join(self.sequence)}",
                            event_ids=tuple(e.event_id for e in chain_events),
                            evidence={
                                "chain": [e.tool_name for e in chain_events],
                            }
                        )
                    )
                    state_idx = 0
                    chain_events = []

        return violations
