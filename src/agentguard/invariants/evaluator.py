"""Evaluator for security invariant rules."""

from __future__ import annotations

import uuid
from typing import Sequence

from agentguard.events.models import ToolEvent
from agentguard.policy.models import RiskLevel
from agentguard.invariants.models import InvariantViolation, RuleScope
from agentguard.invariants.rules import SecurityInvariantRule
from agentguard.context.models import SecurityContext
from agentguard.logging import get_logger

logger = get_logger(__name__)


class InvariantEvaluator:
    """Safely evaluates a sequence of invariant rules over a tool trajectory."""

    def evaluate(
        self,
        events: Sequence[ToolEvent],
        invariants: Sequence[SecurityInvariantRule],
        context: SecurityContext | None = None,
    ) -> list[InvariantViolation]:
        """Evaluate all enabled invariants.

        Returns
        -------
        list[InvariantViolation]
            A deterministically ordered list of invariant violations.
            If a rule crashes, it produces a CRITICAL failure violation.
        """
        all_violations = []

        for rule in invariants:
            if not rule.invariant.enabled:
                continue

            if rule.invariant.scope == RuleScope.TASK:
                if not context or not context.task_contract:
                    continue
                
            try:
                violations = rule.evaluate(events, context=context)
                all_violations.extend(violations)
            except Exception as e:
                logger.exception(
                    "Security invariant rule failed during evaluation", 
                    extra={"invariant_id": rule.invariant.invariant_id}
                )
                failure_violation = InvariantViolation(
                    violation_id=uuid.uuid4().hex,
                    invariant_id=rule.invariant.invariant_id,
                    severity=RiskLevel.CRITICAL,
                    description="The invariant rule encountered an unexpected error during evaluation.",
                    event_ids=(),
                    evidence={"error": str(e)},
                )
                all_violations.append(failure_violation)

        # Deterministic ordering: severity, invariant_id, event_ids
        # severity enum mapping requires converting to integer or string value.
        # Enums can be compared by string or int safely if configured.
        # We'll use the `.value` string for sorting, or map to an integer if strict rank is needed.
        # RiskLevel mapping: None=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4
        # We want descending severity typically, but prompt says "severity, invariant_id, event_ids".
        # Python sort is stable, we can sort forward.
        def _risk_weight(level: RiskLevel) -> int:
            if level == RiskLevel.CRITICAL: return 4
            if level == RiskLevel.HIGH: return 3
            if level == RiskLevel.MEDIUM: return 2
            if level == RiskLevel.LOW: return 1
            return 0

        all_violations.sort(key=lambda v: (
            -_risk_weight(v.severity),  # descending severity
            v.invariant_id,
            v.event_ids
        ))
        
        return all_violations
