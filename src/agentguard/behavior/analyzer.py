"""Engine for executing deterministic behavioral rules."""

from __future__ import annotations

import uuid
from typing import Sequence

from agentguard.events.models import ToolEvent
from agentguard.policy.models import RiskLevel
from agentguard.behavior.models import BehaviorFinding
from agentguard.behavior.rules import BehaviorRule
from agentguard.logging import get_logger

logger = get_logger(__name__)


class BehaviorAnalyzer:
    """Engine that runs a sequence of events against a list of behavior rules."""

    def __init__(self, rules: list[BehaviorRule] | None = None) -> None:
        self.rules = rules or []

    def analyze(self, events: Sequence[ToolEvent]) -> list[BehaviorFinding]:
        """Analyze a sequence of events across all rules.

        Returns
        -------
        list[BehaviorFinding]
            A deterministically ordered list of findings from the rules.
            If a rule fails with an exception, it generates a CRITICAL failure finding.
        """
        all_findings = []

        for rule in self.rules:
            try:
                findings = rule.evaluate(events)
                all_findings.extend(findings)
            except Exception as e:
                # Do not expose traceback in finding per requirements
                logger.exception("Behavior rule failed during evaluation", extra={"rule_id": rule.id})
                failure_finding = BehaviorFinding(
                    finding_id=uuid.uuid4().hex,
                    rule_id=rule.id,
                    severity=RiskLevel.CRITICAL,
                    title="Analyzer Rule Failure",
                    description="The rule encountered an unexpected error during evaluation.",
                    event_ids=(),
                    evidence={"error": str(e)},
                    confidence=1.0,
                )
                all_findings.append(failure_finding)

        # Deterministic ordering: sort by timestamp/event ordering implicitly if generated that way.
        # To guarantee true determinism across multiple runs, sort by rule_id, then finding_id
        # However, finding_id is a UUID which is random. So we should sort by rule_id and then
        # severity or first event_id. 
        # Actually, python list.extend preserves the deterministic order of execution.
        # But we sort by rule_id and severity to be perfectly stable and predictable.
        
        all_findings.sort(key=lambda f: (f.rule_id, f.severity.value, f.event_ids))
        
        return all_findings
