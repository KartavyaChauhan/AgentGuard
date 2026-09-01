"""Tests for the Trajectory Risk Engine."""

import pytest
import datetime
import uuid

from agentguard.events.models import ToolEvent
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.models import ExecutionStatus
from agentguard.behavior.models import BehaviorFinding
from agentguard.risk.models import RiskSeverity, RiskTrend
from agentguard.risk.engine import TrajectoryRiskEngine
from agentguard.risk.rules import evaluate_event, evaluate_finding

def _evt(tool_name: str, args: dict | None = None, action: PolicyAction = PolicyAction.ALLOW, status: ExecutionStatus = ExecutionStatus.EXECUTED) -> ToolEvent:
    return ToolEvent(
        event_id=uuid.uuid4().hex,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        session_id="test-session",
        agent_id="test-agent",
        tool_name=tool_name,
        arguments=args or {},
        policy_action=action,
        risk_level=RiskLevel.LOW,
        execution_status=status
    )

def _find(severity: RiskLevel) -> BehaviorFinding:
    return BehaviorFinding(
        finding_id=uuid.uuid4().hex,
        rule_id="test_rule",
        severity=severity,
        title=f"{severity.value} finding",
        description="A finding",
        event_ids=("evt-1",),
        evidence={},
        confidence=1.0
    )

def test_evaluate_event_normal():
    pts, reason = evaluate_event(_evt("calculate", {"expression": "2+2"}))
    assert pts == 0
    assert "Normal calculate" in reason

def test_evaluate_event_sensitive_read():
    pts, reason = evaluate_event(_evt("read_file", {"path": "/var/secrets/passwd"}))
    assert pts == 30
    assert "passwd" in reason

def test_evaluate_event_safe_read():
    pts, reason = evaluate_event(_evt("read_file", {"path": "main.py"}))
    assert pts == 0

def test_evaluate_event_network():
    pts, reason = evaluate_event(_evt("http_request", {"url": "http://evil.com"}))
    assert pts == 10

def test_evaluate_event_shell():
    pts, reason = evaluate_event(_evt("shell", {"command": "ls"}))
    assert pts == 15

def test_evaluate_event_privileged():
    pts, reason = evaluate_event(_evt("sudo", {"command": "rm -rf"}))
    assert pts == 25

def test_evaluate_event_force_push():
    pts, reason = evaluate_event(_evt("git_push_force"))
    assert pts == 20
    pts, reason = evaluate_event(_evt("git_push", {"force": True}))
    assert pts == 20

def test_evaluate_event_failed():
    pts, reason = evaluate_event(_evt("read_file", status=ExecutionStatus.FAILED))
    assert pts == 5

def test_evaluate_event_approval_required():
    pts, reason = evaluate_event(_evt("dangerous_op", action=PolicyAction.REQUIRE_APPROVAL))
    assert pts == 10

def test_evaluate_finding_critical():
    pts, reason = evaluate_finding(_find(RiskLevel.CRITICAL))
    assert pts == 30

def test_evaluate_finding_high():
    pts, reason = evaluate_finding(_find(RiskLevel.HIGH))
    assert pts == 20

def test_evaluate_finding_medium():
    pts, reason = evaluate_finding(_find(RiskLevel.MEDIUM))
    assert pts == 10

def test_evaluate_finding_low():
    pts, reason = evaluate_finding(_find(RiskLevel.LOW))
    assert pts == 5

def test_engine_zero_risk():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("calculate")], [])
    assert assessment.score == 0
    assert assessment.severity == RiskSeverity.LOW

def test_engine_normal_events():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("ls"), _evt("pwd")], [])
    assert assessment.score == 0

def test_engine_sensitive_file():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("read_file", {"path": ".env"})], [])
    assert assessment.score == 30
    assert assessment.severity == RiskSeverity.MEDIUM

def test_engine_network():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("fetch")], [])
    assert assessment.score == 10

def test_engine_shell():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("bash")], [])
    assert assessment.score == 15

def test_engine_privileged_action():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("privileged_action")], [])
    assert assessment.score == 25

def test_engine_failed_execution():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("ls", status=ExecutionStatus.FAILED)], [])
    assert assessment.score == 5

def test_engine_combo_sensitive_net():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("read_file", {"path": ".env"}), _evt("fetch")], [])
    assert assessment.score == 30 + 10 + 20 # event(30) + event(10) + combo(20) = 60
    assert assessment.severity == RiskSeverity.HIGH

def test_engine_combo_sensitive_encode_net():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("read_file", {"path": ".env"}), _evt("base64_encode"), _evt("fetch")], [])
    assert assessment.score == 30 + 0 + 10 + 30 # combo gives 30
    assert assessment.severity == RiskSeverity.HIGH

def test_engine_combo_read_shell_net():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("read_file", {"path": ".env"}), _evt("shell"), _evt("fetch")], [])
    # event(30) + event(15) + event(10) + combo:sensitive_net(20) + combo:read_shell_net(25) = 100
    assert assessment.score == 100
    assert assessment.severity == RiskSeverity.CRITICAL

def test_engine_combo_normal_priv():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("calculate"), _evt("sudo")], [])
    assert assessment.score == 0 + 25 + 20
    assert assessment.severity == RiskSeverity.MEDIUM

def test_engine_combo_repeated_failures():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [
        _evt("ls", status=ExecutionStatus.FAILED),
        _evt("ls", status=ExecutionStatus.FAILED),
        _evt("ls", status=ExecutionStatus.FAILED)
    ], [])
    assert assessment.score == 5 + 5 + 5 + 15

def test_engine_score_clamping():
    engine = TrajectoryRiskEngine()
    events = [_evt("read_file", {"path": ".env"}) for _ in range(5)]
    assessment = engine.evaluate("s1", events, [])
    assert assessment.score == 100
    assert assessment.severity == RiskSeverity.CRITICAL

def test_engine_duplicate_contribution_prevention():
    engine = TrajectoryRiskEngine()
    evt = _evt("read_file", {"path": ".env"})
    # Even if same event passed twice, only counted once
    assessment = engine.evaluate("s1", [evt, evt], [])
    assert assessment.score == 30

def test_engine_deterministic_ordering():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("read_file", {"path": ".env"}), _evt("fetch")], [])
    # 30 pt contribution, 20 pt combo, 10 pt contribution
    pts = [c.points for c in assessment.contributions]
    assert pts == [30, 20, 10]

def test_engine_risk_trend_stable():
    engine = TrajectoryRiskEngine()
    a1 = engine.evaluate("s1", [_evt("ls")], [])
    a2 = engine.evaluate("s1", [_evt("ls")], [])
    assert a1.trend == RiskTrend.STABLE
    assert a2.trend == RiskTrend.STABLE

def test_engine_risk_trend_increasing():
    engine = TrajectoryRiskEngine()
    a1 = engine.evaluate("s1", [_evt("ls")], [])
    a2 = engine.evaluate("s1", [_evt("read_file", {"path": ".env"})], [])
    assert a2.trend == RiskTrend.INCREASING

def test_engine_risk_trend_decreasing():
    engine = TrajectoryRiskEngine()
    a1 = engine.evaluate("s1", [_evt("read_file", {"path": ".env"})], [])
    a2 = engine.evaluate("s1", [_evt("ls")], [])
    assert a2.trend == RiskTrend.DECREASING

def test_engine_safe_event_decay():
    engine = TrajectoryRiskEngine(decay_enabled=True)
    events = [_evt("read_file", {"path": ".env"}), _evt("ls"), _evt("ls")]
    assessment = engine.evaluate("s1", events, [])
    # 30 pts for read, then 2 safe events = -10 decay = 20
    assert assessment.score == 20

def test_engine_decay_floor():
    engine = TrajectoryRiskEngine(decay_enabled=True)
    events = [_evt("read_file", {"path": ".env"})] + [_evt("ls")] * 10
    assessment = engine.evaluate("s1", events, [])
    # 30 pts for read, then 10 safe events = -50 decay. But combos=0 so min_score=0.
    assert assessment.score == 0

def test_engine_decay_combo_floor():
    engine = TrajectoryRiskEngine(decay_enabled=True)
    events = [_evt("read_file", {"path": ".env"}), _evt("fetch")] + [_evt("ls")] * 10
    assessment = engine.evaluate("s1", events, [])
    # read(30) + fetch(10) + combo(20) = 60
    # 10 safe events = -50 decay. Combo total is 20. Floor is 20.
    # 60 - 50 = 10, which is < 20. So it should floor at 20.
    assert assessment.score == 20

def test_no_raw_secrets_in_explanation():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("read_file", {"path": "/etc/secrets/SUPER_SECRET_KEY"})], [])
    reasons_text = " ".join(assessment.reasons)
    assert "SUPER_SECRET_KEY" in reasons_text
    assert "/etc/secrets" not in reasons_text  # path is sanitized

def test_json_serialization():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [_evt("ls")], [])
    d = assessment.to_dict()
    assert d["score"] == 0
    assert d["severity"] == "LOW"
    assert d["trend"] == "STABLE"

def test_findings_scoring():
    engine = TrajectoryRiskEngine()
    assessment = engine.evaluate("s1", [], [_find(RiskLevel.HIGH)])
    assert assessment.score == 20
    assert assessment.severity == RiskSeverity.LOW

def test_all_severities():
    engine = TrajectoryRiskEngine()
    assert engine.evaluate("s1", [_evt("fetch")], []).severity == RiskSeverity.LOW
    assert engine.evaluate("s2", [_evt("read_file", {"path": ".env"})], []).severity == RiskSeverity.MEDIUM
    assert engine.evaluate("s3", [_evt("read_file", {"path": ".env"}), _evt("fetch")], []).severity == RiskSeverity.HIGH
    assert engine.evaluate("s4", [_evt("read_file", {"path": ".env"}), _evt("fetch"), _evt("shell")], []).severity == RiskSeverity.CRITICAL
