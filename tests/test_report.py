"""Tests for the security reporting system and CLI outputs."""

import pytest
import json
from unittest.mock import patch, MagicMock
from io import StringIO

from agentguard.report.models import SecurityAssessment
from agentguard.invariants.models import InvariantViolation
from agentguard.policy.models import RiskLevel
from agentguard.cli import run_report_command


def _violation(severity: RiskLevel) -> InvariantViolation:
    return InvariantViolation(
        violation_id="v1",
        invariant_id="i1",
        severity=severity,
        description="test",
        event_ids=(),
        evidence={}
    )


class TestSecurityAssessment:
    def test_security_score_calculation(self):
        violations = (
            _violation(RiskLevel.CRITICAL), # -30
            _violation(RiskLevel.HIGH),     # -15
            _violation(RiskLevel.MEDIUM),   # -7
            _violation(RiskLevel.LOW),      # -2
        )
        # 100 - 30 - 15 - 7 - 2 = 46
        # missed = 1 -> -30 = 16
        assessment = SecurityAssessment.calculate(
            violations=violations,
            false_positive_count=0,
            tested_scenarios=10,
            protected_scenarios=9,
            missed_scenarios=1
        )
        
        assert assessment.score == 16
        assert assessment.critical_count == 1
        assert assessment.high_count == 1
        assert assessment.medium_count == 1
        assert assessment.low_count == 1
        
    def test_severity_weighting(self):
        assessment = SecurityAssessment.calculate(
            violations=(_violation(RiskLevel.CRITICAL), _violation(RiskLevel.CRITICAL)),
            false_positive_count=0,
            tested_scenarios=10,
            protected_scenarios=10,
            missed_scenarios=0
        )
        assert assessment.score == 40  # 100 - 60
        
    def test_score_clamping_bottom(self):
        violations = tuple([_violation(RiskLevel.CRITICAL)] * 5)
        assessment = SecurityAssessment.calculate(
            violations=violations,
            false_positive_count=0,
            tested_scenarios=10,
            protected_scenarios=5,
            missed_scenarios=5
        )
        assert assessment.score == 0  # 100 - 150 - 150 = -200 -> clamped to 0
        
    def test_score_clamping_top(self):
        assessment = SecurityAssessment.calculate(
            violations=(),
            false_positive_count=0,
            tested_scenarios=10,
            protected_scenarios=10,
            missed_scenarios=0
        )
        assert assessment.score == 100
        
    def test_deterministic_report(self):
        v1 = _violation(RiskLevel.CRITICAL)
        assessment1 = SecurityAssessment.calculate((v1,), 0, 10, 10, 0)
        assessment2 = SecurityAssessment.calculate((v1,), 0, 10, 10, 0)
        assert assessment1 == assessment2


class TestCLIReport:
    @patch("sys.stdout", new_callable=StringIO)
    def test_cli_report_text(self, mock_stdout):
        # We can run the built-in command which uses BenchmarkRunner underneath
        # This will take a moment as it runs all scenarios
        run_report_command(json_output=False)
        output = mock_stdout.getvalue()
        
        assert "AgentGuard Security Report" in output
        assert "Security Score:" in output
        assert "CRITICAL:" in output
        assert "Protected scenarios:" in output
        assert "False positives: 0" in output
        assert "Missed scenarios: 1" in output

    @patch("sys.stdout", new_callable=StringIO)
    def test_cli_report_json(self, mock_stdout):
        run_report_command(json_output=True)
        output = mock_stdout.getvalue()
        
        data = json.loads(output)
        assert "score" in data
        assert "counts" in data
        assert "protected" in data
        assert "false_positives" in data
        assert data["false_positives"] == 0
        assert data["missed"] == 1
