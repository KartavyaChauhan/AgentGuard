"""Tests for the Unified Trust Decision Engine."""

import pytest
import datetime
import json

from agentguard.trust.models import TrustDecision, TrustAssessment
from agentguard.trust.policy import TrustConfig, DEFAULT_TRUST_CONFIG
from agentguard.trust.engine import TrustEngine
from agentguard.trust.report import TrustReport

from agentguard.events.models import ToolEvent
from agentguard.context.models import SecurityContext
from agentguard.policy.models import PolicyDecision, PolicyAction, RiskLevel
from agentguard.behavior.models import BehaviorFinding
from agentguard.invariants.models import InvariantViolation
from agentguard.outcome.models import OutcomeAssessment, TaskContract
from agentguard.risk.models import RiskAssessment, RiskSeverity, RiskTrend
from agentguard.execution.models import ExecutionStatus


@pytest.fixture
def empty_context():
    return SecurityContext(session_id="sess-1", agent_id="agent-1")


@pytest.fixture
def context_with_contract():
    contract = TaskContract(
        contract_id="c-1",
        task_name="test-task",
        required_evidence=("success",)
    )
    return SecurityContext(session_id="sess-1", agent_id="agent-1", task_contract=contract)


@pytest.fixture
def engine():
    return TrustEngine()


def _dummy_outcome(satisfied=True, observed=(), missing=()):
    return OutcomeAssessment(
        contract_id="c-1",
        satisfied=satisfied,
        missing_evidence=missing,
        observed_evidence=observed,
        failed_evidence=(),
        evidence_ids=(),
        explanation="x"
    )

def _dummy_risk(score=10, severity=RiskSeverity.LOW):
    return RiskAssessment(
        session_id="sess-1",
        score=score,
        severity=severity,
        trend=RiskTrend.STABLE,
        contributions=(),
        reasons=()
    )


def test_trust_decision_enum():
    """Verify enum values."""
    assert TrustDecision.TRUSTED.value == "TRUSTED"
    assert TrustDecision.BLOCKED.value == "BLOCKED"
    assert TrustDecision.UNVERIFIED.value == "UNVERIFIED"
    assert TrustDecision.RISKY.value == "RISKY"
    assert TrustDecision.ERROR.value == "ERROR"


def test_trust_assessment_immutability():
    """Verify TrustAssessment is immutable and defensive."""
    assessment = TrustAssessment(
        decision=TrustDecision.TRUSTED,
        session_id="sess-1",
        agent_id="agent-1",
        task_contract_id="c-1",
        risk_score=10,
        risk_severity="LOW",
        policy_status="PASS",
        behavior_status="CLEAN",
        invariant_status="PASS",
        outcome_status="SATISFIED",
        confidence=1.0,
        reasons=("Reason 1",),
        evidence={"key": True},
        findings=(),
        violations=()
    )

    with pytest.raises(Exception):
        assessment.decision = TrustDecision.BLOCKED

    # The dictionary passed in should be defensively copied and booleanized
    assert assessment.evidence["key"] is True


def test_error_handling(engine, empty_context):
    """Verify engine handles errors gracefully by returning ERROR status."""
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=None,  # Will raise AttributeError
        risk_assessment=None
    )
    
    assert assessment.decision == TrustDecision.ERROR
    assert assessment.confidence == 0.0


def test_blocked_by_policy(engine, empty_context):
    """Verify policy DENY results in BLOCKED."""
    
    decisions = [PolicyDecision(action=PolicyAction.DENY, reason="test")]
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=decisions,
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.decision == TrustDecision.BLOCKED
    assert assessment.policy_status == "DENIED"
    assert "blocked by security policy" in assessment.reasons[0].lower()


def test_blocked_by_denied_event(engine, empty_context):
    """Verify a DENIED event results in BLOCKED."""
    
    event = ToolEvent(
        event_id="e1",
        session_id="sess-1",
        agent_id="a1",
        tool_name="test",
        arguments={},
        policy_action=PolicyAction.DENY,
        risk_level=RiskLevel.LOW,
        execution_status=ExecutionStatus.DENIED,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        duration_ms=0.0
    )
    
    assessment = engine.evaluate(
        events=[event],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.decision == TrustDecision.BLOCKED
    assert assessment.policy_status == "DENIED"


def test_blocked_by_invariant(engine, empty_context):
    """Verify a critical invariant violation results in BLOCKED."""
    
    violations = [InvariantViolation(
        violation_id="v1", invariant_id="inv1", severity=RiskLevel.CRITICAL,
        description="x", event_ids=(), evidence={}
    )]
    
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=violations,
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.decision == TrustDecision.BLOCKED
    assert assessment.invariant_status == "VIOLATED"
    assert "blocked by security invariant" in assessment.reasons[0].lower()


def test_risky_by_finding(engine, empty_context):
    """Verify high severity behavior finding results in RISKY."""
    
    findings = [BehaviorFinding(
        finding_id="f1", rule_id="r1", severity=RiskLevel.HIGH, title="",
        description="x", event_ids=(), evidence={}, confidence=1.0
    )]
    
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=findings,
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk(score=20, severity=RiskSeverity.MEDIUM)
    )
    
    assert assessment.decision == TrustDecision.RISKY
    assert assessment.behavior_status == "FLAGGED"


def test_risky_by_score(engine, empty_context):
    """Verify high risk score results in RISKY."""
    
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk(score=60, severity=RiskSeverity.HIGH)
    )
    
    assert assessment.decision == TrustDecision.RISKY


def test_unverified(engine, context_with_contract):
    """Verify ALLOW combined with NOT_SATISFIED outcome results in UNVERIFIED."""
    
    assessment = engine.evaluate(
        events=[],
        context=context_with_contract,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(satisfied=False),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.decision == TrustDecision.UNVERIFIED
    assert "outcome evidence was not established" in assessment.reasons[0]


def test_trusted(engine, context_with_contract):
    """Verify clean execution with SATISFIED outcome results in TRUSTED."""
    
    assessment = engine.evaluate(
        events=[],
        context=context_with_contract,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(satisfied=True, observed=("success",)),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.decision == TrustDecision.TRUSTED
    assert assessment.evidence["success"] is True


def test_precedence_blocked_over_risky(engine, empty_context):
    """Verify BLOCKED takes precedence over RISKY."""
    
    decisions = [PolicyDecision(action=PolicyAction.DENY, reason="test")]
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=decisions,
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk(score=90, severity=RiskSeverity.CRITICAL)
    )
    
    assert assessment.decision == TrustDecision.BLOCKED


def test_precedence_risky_over_unverified(engine, empty_context):
    """Verify RISKY takes precedence over UNVERIFIED."""
    
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(satisfied=False),
        risk_assessment=_dummy_risk(score=60, severity=RiskSeverity.HIGH)
    )
    
    assert assessment.decision == TrustDecision.RISKY


def test_report_json(engine, empty_context):
    """Verify JSON output format."""
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    
    report = TrustReport(assessment)
    data = json.loads(report.to_json())
    
    assert data["decision"] == "TRUSTED"
    assert data["risk_score"] == 10
    assert data["risk_severity"] == "LOW"
    assert data["policy_status"] == "PASS"


def test_report_text(engine, empty_context):
    """Verify text output format."""
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    
    report = TrustReport(assessment)
    text = report.to_text()
    
    assert "AgentGuard Trust Assessment" in text
    assert "Decision: TRUSTED" in text
    assert "Policy: PASS" in text

def test_multiple_findings(engine, empty_context):
    """Verify engine can handle multiple behavior findings."""
    findings = [
        BehaviorFinding(finding_id="f1", rule_id="r1", severity=RiskLevel.MEDIUM, title="", description="x", event_ids=(), evidence={}, confidence=1.0),
        BehaviorFinding(finding_id="f2", rule_id="r2", severity=RiskLevel.HIGH, title="", description="x", event_ids=(), evidence={}, confidence=1.0)
    ]
    
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=findings,
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk(score=20, severity=RiskSeverity.MEDIUM)
    )
    
    assert assessment.decision == TrustDecision.RISKY
    assert "f1" in assessment.findings
    assert "f2" in assessment.findings

def test_multiple_violations(engine, empty_context):
    """Verify engine can handle multiple invariant violations."""
    violations = [
        InvariantViolation(violation_id="v1", invariant_id="inv1", severity=RiskLevel.LOW, description="x", event_ids=(), evidence={}),
        InvariantViolation(violation_id="v2", invariant_id="inv2", severity=RiskLevel.CRITICAL, description="x", event_ids=(), evidence={})
    ]
    
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=violations,
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.decision == TrustDecision.BLOCKED
    assert "inv1" in assessment.violations
    assert "inv2" in assessment.violations

def test_allow_not_trusted(engine, context_with_contract):
    """Verify ALLOW policy doesn't automatically mean TRUSTED if evidence is missing."""
    decisions = [PolicyDecision(action=PolicyAction.ALLOW, reason="test")]
    assessment = engine.evaluate(
        events=[],
        context=context_with_contract,
        policy_decisions=decisions,
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(satisfied=False),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.policy_status == "PASS"
    assert assessment.decision == TrustDecision.UNVERIFIED

def test_evidence_sanitization(engine, context_with_contract):
    """Verify evidence values are properly normalized into boolean flags."""
    assessment = engine.evaluate(
        events=[],
        context=context_with_contract,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(satisfied=True, observed=("tests_passed",)),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.evidence["tests_passed"] is True
    assert len(assessment.evidence) == 1

def test_deterministic_ordering(engine, empty_context):
    """Verify the reasons list is deterministically deduplicated without losing order."""
    violations = [
        InvariantViolation(violation_id="v1", invariant_id="inv1", severity=RiskLevel.CRITICAL, description="x", event_ids=(), evidence={}),
        InvariantViolation(violation_id="v2", invariant_id="inv1", severity=RiskLevel.CRITICAL, description="x", event_ids=(), evidence={})
    ]
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=violations,
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.decision == TrustDecision.BLOCKED
    reasons = assessment.reasons
    assert len([r for r in reasons if "inv1" in r]) == 1

def test_risk_status_override(engine, empty_context):
    """RISKY should not override ERROR."""
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=None,  # triggers error
        risk_assessment=_dummy_risk(score=99, severity=RiskSeverity.CRITICAL)
    )
    assert assessment.decision == TrustDecision.ERROR

def test_report_text_no_evidence(engine, empty_context):
    """Verify text report when there is no evidence."""
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    
    report = TrustReport(assessment)
    text = report.to_text()
    assert "(no evidence required or provided)" in text

def test_policy_require_approval_unapproved(engine, empty_context):
    decisions = [PolicyDecision(action=PolicyAction.REQUIRE_APPROVAL, reason="test")]
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=decisions,
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.decision == TrustDecision.BLOCKED

def test_policy_allow_with_denied_event(engine, empty_context):
    event = ToolEvent(
        event_id="e1", session_id="sess-1", agent_id="a1", tool_name="test", arguments={},
        policy_action=PolicyAction.ALLOW, risk_level=RiskLevel.LOW, execution_status=ExecutionStatus.DENIED,
        timestamp=datetime.datetime.now(datetime.timezone.utc), duration_ms=0.0
    )
    assessment = engine.evaluate(
        events=[event],
        context=empty_context,
        policy_decisions=[PolicyDecision(action=PolicyAction.ALLOW, reason="test")],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    
    assert assessment.decision == TrustDecision.BLOCKED

def test_trust_config_overrides():
    config = TrustConfig(risky_score_threshold=90)
    assert config.risky_score_threshold == 90
    assert config.critical_score_threshold == 80

def test_trust_decision_trusted():
    assert TrustDecision.TRUSTED.name == "TRUSTED"

def test_trust_decision_blocked():
    assert TrustDecision.BLOCKED.name == "BLOCKED"

def test_trust_decision_risky():
    assert TrustDecision.RISKY.name == "RISKY"

def test_trust_decision_unverified():
    assert TrustDecision.UNVERIFIED.name == "UNVERIFIED"

def test_trust_decision_error():
    assert TrustDecision.ERROR.name == "ERROR"

def test_trust_assessment_dataclass():
    a = TrustAssessment(
        decision=TrustDecision.TRUSTED,
        session_id="1",
        agent_id="2",
        task_contract_id="3",
        risk_score=0,
        risk_severity="LOW",
        policy_status="PASS",
        behavior_status="CLEAN",
        invariant_status="PASS",
        outcome_status="SATISFIED",
        confidence=1.0,
        reasons=(),
        evidence={},
        findings=(),
        violations=()
    )
    assert a.session_id == "1"

def test_trust_report_empty():
    a = TrustAssessment(
        decision=TrustDecision.TRUSTED,
        session_id="1",
        agent_id="2",
        task_contract_id="3",
        risk_score=0,
        risk_severity="LOW",
        policy_status="PASS",
        behavior_status="CLEAN",
        invariant_status="PASS",
        outcome_status="SATISFIED",
        confidence=1.0,
        reasons=(),
        evidence={},
        findings=(),
        violations=()
    )
    rep = TrustReport(a)
    assert rep.to_json()

def test_empty_violations(engine, empty_context):
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    assert len(assessment.violations) == 0

def test_empty_findings(engine, empty_context):
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(),
        risk_assessment=_dummy_risk()
    )
    assert len(assessment.findings) == 0

def test_evidence_false(engine, empty_context):
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(satisfied=True, missing=("test",)),
        risk_assessment=_dummy_risk()
    )
    assert assessment.evidence["test"] is False

def test_report_text_evidence_false(engine, empty_context):
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(satisfied=True, missing=("test",)),
        risk_assessment=_dummy_risk()
    )
    rep = TrustReport(assessment)
    assert "✗ test" in rep.to_text()

def test_report_text_evidence_true(engine, empty_context):
    assessment = engine.evaluate(
        events=[],
        context=empty_context,
        policy_decisions=[],
        behavior_findings=[],
        invariant_violations=[],
        outcome_assessment=_dummy_outcome(satisfied=True, observed=("test",)),
        risk_assessment=_dummy_risk()
    )
    rep = TrustReport(assessment)
    assert "✓ test" in rep.to_text()
