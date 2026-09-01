"""Tests for the security context and rule scoping logic."""

import pytest
from typing import Sequence

from agentguard.context.models import SecurityContext
from agentguard.outcome.models import TaskContract
from agentguard.invariants.models import SecurityInvariant, InvariantViolation, RuleScope
from agentguard.invariants.rules import RequiredEvidenceRule, SecurityInvariantRule, NoSensitiveDataExfiltrationRule
from agentguard.invariants.evaluator import InvariantEvaluator
from agentguard.events.models import ToolEvent
from agentguard.policy.models import RiskLevel
import datetime
import uuid


def _event(name: str) -> ToolEvent:
    return ToolEvent(
        event_id=uuid.uuid4().hex,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        session_id="s1",
        agent_id="a1",
        tool_name=name,
        arguments={},
        policy_action="ALLOW",
        risk_level=RiskLevel.LOW,
        execution_status="EXECUTED"
    )


class TestSecurityContext:
    def test_context_immutability(self):
        ctx = SecurityContext(session_id="s1", agent_id="a1")
        with pytest.raises(Exception):  # FrozenInstanceError
            ctx.session_id = "s2"

    def test_context_defensive_copy(self):
        meta = {"key": "val"}
        ctx = SecurityContext(session_id="s1", agent_id="a1", metadata=meta)
        meta["key"] = "changed"
        assert ctx.metadata["key"] == "val"


class TestContextAwareRules:
    def test_required_evidence_with_contract(self):
        rule = RequiredEvidenceRule()
        contract = TaskContract(contract_id="c1", task_name="Task", required_evidence=("tests_passed",))
        ctx = SecurityContext(session_id="s1", agent_id="a1", task_contract=contract)
        events = [_event("read_file")]
        
        violations = rule.evaluate(events, context=ctx)
        assert len(violations) == 1
        assert violations[0].invariant_id == "required-test-evidence"

    def test_required_evidence_without_contract(self):
        rule = RequiredEvidenceRule()
        ctx = SecurityContext(session_id="s1", agent_id="a1", task_contract=None)
        events = [_event("read_file")]
        
        violations = rule.evaluate(events, context=ctx)
        assert len(violations) == 0

    def test_backward_compatibility(self):
        # Backwards compat: If rule is initialized with a contract, it uses it if context lacks one
        contract = TaskContract(contract_id="c1", task_name="Task", required_evidence=("tests_passed",))
        rule = RequiredEvidenceRule(contract=contract)
        events = [_event("read_file")]
        
        violations = rule.evaluate(events)
        assert len(violations) == 1
        assert violations[0].invariant_id == "required-test-evidence"
        
    def test_backward_compatibility_context_override(self):
        # Backwards compat: context contract overrides init contract
        init_contract = TaskContract(contract_id="c1", task_name="Task", required_evidence=("tests_passed",))
        rule = RequiredEvidenceRule(contract=init_contract)
        
        # Override with empty contract (or different contract) in context
        ctx = SecurityContext(session_id="s1", agent_id="a1", task_contract=None)
        events = [_event("read_file")]
        
        violations = rule.evaluate(events, context=ctx)
        assert len(violations) == 0


class DummyTaskRule(SecurityInvariantRule):
    def __init__(self):
        self._invariant = SecurityInvariant(
            invariant_id="dummy-task",
            name="Dummy Task",
            description="",
            severity=RiskLevel.LOW,
            scope=RuleScope.TASK
        )

    @property
    def invariant(self):
        return self._invariant

    def evaluate(self, events, context=None):
        return [self._create_violation("test", (), {})]


class DummySessionRule(SecurityInvariantRule):
    def __init__(self):
        self._invariant = SecurityInvariant(
            invariant_id="dummy-session",
            name="Dummy Session",
            description="",
            severity=RiskLevel.LOW,
            scope=RuleScope.SESSION
        )

    @property
    def invariant(self):
        return self._invariant

    def evaluate(self, events, context=None):
        return [self._create_violation("test", (), {})]


class TestInvariantEvaluatorScope:
    def test_task_rule_skipped_without_contract(self):
        evaluator = InvariantEvaluator()
        rules = [DummyTaskRule()]
        ctx = SecurityContext(session_id="s1", agent_id="a1", task_contract=None)
        
        violations = evaluator.evaluate([], rules, context=ctx)
        assert len(violations) == 0
        
    def test_task_rule_skipped_without_context(self):
        evaluator = InvariantEvaluator()
        rules = [DummyTaskRule()]
        
        violations = evaluator.evaluate([], rules)
        assert len(violations) == 0
        
    def test_task_rule_runs_with_contract(self):
        evaluator = InvariantEvaluator()
        rules = [DummyTaskRule()]
        contract = TaskContract("c1", "Task", ("tests_passed",))
        ctx = SecurityContext(session_id="s1", agent_id="a1", task_contract=contract)
        
        violations = evaluator.evaluate([], rules, context=ctx)
        assert len(violations) == 1
        
    def test_session_rule_runs_without_context(self):
        evaluator = InvariantEvaluator()
        rules = [DummySessionRule()]
        
        violations = evaluator.evaluate([], rules)
        assert len(violations) == 1
        
    def test_session_rule_runs_with_context(self):
        evaluator = InvariantEvaluator()
        rules = [DummySessionRule()]
        ctx = SecurityContext(session_id="s1", agent_id="a1", task_contract=None)
        
        violations = evaluator.evaluate([], rules, context=ctx)
        assert len(violations) == 1
