"""Runner for executing security test cases against invariants."""

from __future__ import annotations

from typing import Sequence

from agentguard.invariants.models import (
    SecurityTestCase,
    SecurityTestResult,
    SecurityTestReport,
)
from agentguard.invariants.rules import SecurityInvariantRule
from agentguard.invariants.evaluator import InvariantEvaluator


class SecurityTestRunner:
    """Runs a suite of security test cases to detect invariant regressions."""

    def __init__(self, rules: Sequence[SecurityInvariantRule]) -> None:
        self.rules = rules
        self.evaluator = InvariantEvaluator()

    def run(self, test_cases: Sequence[SecurityTestCase]) -> SecurityTestReport:
        """Evaluate all test cases and return a consolidated report."""
        passed_count = 0
        failed_count = 0
        results = []

        for case in test_cases:
            # 1. Evaluate the trajectory
            violations = self.evaluator.evaluate(case.events, self.rules, context=case.context)
            
            # 2. Extract actual invariant IDs that were violated
            # Use a set for comparison, but store as sorted tuple for deterministic output
            actual_ids = sorted(list(set(v.invariant_id for v in violations)))
            expected_ids = sorted(list(set(case.expected_violations)))

            # 3. Compare actual vs expected
            if actual_ids == expected_ids:
                status = "PASS"
                explanation = "Actual violations matched expected violations exactly."
                passed_count += 1
            else:
                status = "FAIL"
                explanation = "Security regression detected! Expected violations did not match actual violations."
                failed_count += 1

            # 4. Produce deterministic result
            results.append(
                SecurityTestResult(
                    test_id=case.test_id,
                    status=status,
                    expected=tuple(expected_ids),
                    actual=tuple(actual_ids),
                    explanation=explanation,
                )
            )

        return SecurityTestReport(
            total_tests=len(test_cases),
            passed=passed_count,
            failed=failed_count,
            results=tuple(results),
        )
