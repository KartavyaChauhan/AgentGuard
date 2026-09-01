"""Evaluation Runner for AgentGuard external benchmarks."""

import time
import datetime
from typing import List, Optional
import uuid

from agentguard.evaluation.models import EvaluationScenario, EvaluationResult, ExpectedOutcome, ActualOutcome
from agentguard.policy import PolicyEngine, ToolRequest, PolicyAction, RiskLevel
from agentguard.events import EventStore, ToolEvent
from agentguard.execution import ExecutionStatus
from agentguard.behavior import BehaviorAnalyzer
from agentguard.invariants import SecurityTestRunner
from agentguard.risk import TrajectoryRiskEngine
from agentguard.context import SecurityContext
from agentguard.outcome import EvidenceEvaluator, TaskContract
from agentguard.trust import TrustEngine


class EvaluationRunner:
    """Executes evaluation scenarios against AgentGuard components."""
    
    def __init__(
        self,
        policy_engine: PolicyEngine,
        event_store: EventStore,
        behavior_analyzer: BehaviorAnalyzer,
        invariant_runner: SecurityTestRunner,
        risk_engine: TrajectoryRiskEngine,
        evidence_evaluator: EvidenceEvaluator,
        trust_engine: TrustEngine,
        baseline_mode: bool = False
    ):
        self.policy_engine = policy_engine
        self.event_store = event_store
        self.behavior_analyzer = behavior_analyzer
        self.invariant_runner = invariant_runner
        self.risk_engine = risk_engine
        self.evidence_evaluator = evidence_evaluator
        self.trust_engine = trust_engine
        self.baseline_mode = baseline_mode
        
    def _evaluate_actual_outcome(self, expected: ExpectedOutcome, blocked: bool, violations: tuple[str, ...], findings: tuple[str, ...]) -> ActualOutcome:
        """Deterministically map expected outcome and AgentGuard state to ActualOutcome."""
        is_security_flagged = blocked or len(violations) > 0 or len(findings) > 0
        
        if expected == ExpectedOutcome.BLOCKED:
            if blocked:
                return ActualOutcome.BLOCKED
            if is_security_flagged:
                return ActualOutcome.DETECTED
            return ActualOutcome.MISSED
            
        if expected == ExpectedOutcome.DETECTED:
            if is_security_flagged:
                return ActualOutcome.DETECTED
            return ActualOutcome.MISSED
            
        if expected in (ExpectedOutcome.SAFE, ExpectedOutcome.ALLOWED):
            if is_security_flagged:
                return ActualOutcome.FALSE_POSITIVE
            return ActualOutcome.SAFE
            
        return ActualOutcome.ERROR

    def run_scenario(self, scenario: EvaluationScenario) -> EvaluationResult:
        session_id = f"eval_{scenario.scenario_id}_{uuid.uuid4().hex[:8]}"
        
        task_contract = None
        if scenario.task_contract:
            task_contract = TaskContract(
                contract_id=scenario.task_contract.get("contract_id", "default"),
                task_name=scenario.task_contract.get("task_name", "eval_task"),
                required_evidence=tuple(scenario.task_contract.get("required_evidence", []))
            )
            
        context = SecurityContext(
            session_id=session_id, 
            agent_id="eval_runner",
            task_contract=task_contract
        )
        
        start_time = time.perf_counter()
        
        blocked = False
        blocked_reason = ""
        total_policy_time = 0.0
        
        # Execute trajectory
        for call in scenario.trajectory:
            request = ToolRequest(tool_name=call.tool_name, arguments=call.arguments)
            
            p_start = time.perf_counter()
            if self.baseline_mode:
                # Bypass policy and just record
                self.event_store.record(
                    ToolEvent(
                        event_id=uuid.uuid4().hex,
                        timestamp=datetime.datetime.now(datetime.timezone.utc),
                        session_id=session_id,
                        agent_id=context.agent_id,
                        tool_name=call.tool_name,
                        arguments=call.arguments,
                        policy_action=PolicyAction.ALLOW,
                        risk_level=RiskLevel.LOW,
                        execution_status=ExecutionStatus.EXECUTED,
                        duration_ms=0.1
                    )
                )
            else:
                try:
                    # In evaluation, if a tool is not provided to executor, it raises an exception if ALLOWED.
                    # We bypass actual execution by just evaluating policy and recording manually.
                    decision = self.policy_engine.evaluate(request)
                    
                    if decision.action in (PolicyAction.DENY, PolicyAction.REQUIRE_APPROVAL):
                        blocked = True
                        blocked_reason = decision.rule_id
                        self.event_store.record(
                            ToolEvent(
                                event_id=uuid.uuid4().hex,
                                timestamp=datetime.datetime.now(datetime.timezone.utc),
                                session_id=session_id,
                                agent_id=context.agent_id,
                                tool_name=call.tool_name,
                                arguments=call.arguments,
                                policy_action=decision.action,
                                risk_level=decision.risk_level,
                                execution_status=ExecutionStatus.DENIED,
                                duration_ms=0.1
                            )
                        )
                        p_end = time.perf_counter()
                        total_policy_time += (p_end - p_start)
                        break # Stop trajectory on block
                    else:
                        self.event_store.record(
                            ToolEvent(
                                event_id=uuid.uuid4().hex,
                                timestamp=datetime.datetime.now(datetime.timezone.utc),
                                session_id=session_id,
                                agent_id=context.agent_id,
                                tool_name=call.tool_name,
                                arguments=call.arguments,
                                policy_action=decision.action,
                                risk_level=decision.risk_level,
                                execution_status=ExecutionStatus.EXECUTED,
                                duration_ms=0.1
                            )
                        )
                except Exception as e:
                    blocked = True
                    blocked_reason = f"error: {str(e)}"
                    self.event_store.record(
                        ToolEvent(
                            event_id=uuid.uuid4().hex,
                            timestamp=datetime.datetime.now(datetime.timezone.utc),
                            session_id=session_id,
                            agent_id=context.agent_id,
                            tool_name=call.tool_name,
                            arguments=call.arguments,
                            policy_action=PolicyAction.DENY,
                            risk_level=RiskLevel.CRITICAL,
                            execution_status=ExecutionStatus.ERROR,
                            duration_ms=0.1
                        )
                    )
                    break
                    
            p_end = time.perf_counter()
            total_policy_time += (p_end - p_start)
            
        a_start = time.perf_counter()
        
        # Post-trajectory analysis
        events = self.event_store.get_session_events(session_id)
        
        # Calculate outcome assessment for trust engine
        if context.task_contract:
            outcome_assessment = self.evidence_evaluator.evaluate(context.task_contract, events)
        else:
            from agentguard.outcome.models import OutcomeAssessment
            outcome_assessment = OutcomeAssessment(
                contract_id="none",
                satisfied=True,
                missing_evidence=(),
                observed_evidence=(),
                failed_evidence=(),
                evidence_ids=(),
                explanation="No contract provided."
            )
        
        findings = tuple()
        violations = tuple()
        risk_score = 0
        risk_severity = "LOW"
        trust_decision_str = None
        
        if not self.baseline_mode:
            findings_objs = self.behavior_analyzer.analyze(events)
            findings = tuple(f.rule_id for f in findings_objs)
            
            invariant_results = self.invariant_runner.evaluator.evaluate(events, self.invariant_runner.rules, context=context)
            violations = tuple(v.invariant_id for v in invariant_results)
            
            risk_assessment = self.risk_engine.evaluate(session_id, events, findings_objs)
            risk_score = risk_assessment.score
            risk_severity = risk_assessment.severity.name

            # Note: We need policy decisions, but we just pass an empty list since the trust engine 
            # also checks the events for DENIED status directly.
            trust_assessment = self.trust_engine.evaluate(
                events=events,
                context=context,
                policy_decisions=[], 
                behavior_findings=findings_objs,
                invariant_violations=invariant_results,
                outcome_assessment=outcome_assessment,
                risk_assessment=risk_assessment
            )
            trust_decision_str = trust_assessment.decision.value

        else:
            # For baseline, everything is skipped, risk is 0, trust is UNVERIFIED/TRUSTED depending on outcome
            # But we don't strictly need a realistic trust decision in baseline.
            trust_decision_str = "RISKY" if not outcome_assessment.satisfied else "TRUSTED"

        a_end = time.perf_counter()
        total_analysis_time = a_end - a_start
        total_exec_time = time.perf_counter() - start_time
        
        actual_outcome = self._evaluate_actual_outcome(scenario.expected_outcome, blocked, violations, findings)
        
        explanation = []
        if blocked: explanation.append(f"Blocked by {blocked_reason}")
        if violations: explanation.append(f"Violations: {', '.join(violations)}")
        if findings: explanation.append(f"Findings: {', '.join(findings)}")
        
        return EvaluationResult(
            scenario_id=scenario.scenario_id,
            expected_outcome=scenario.expected_outcome,
            actual_outcome=actual_outcome,
            violations=violations,
            findings=findings,
            explanation="; ".join(explanation) if explanation else "Safe",
            risk_score=risk_score,
            risk_severity=risk_severity,
            execution_time_ms=total_exec_time * 1000,
            policy_time_ms=total_policy_time * 1000,
            analysis_time_ms=total_analysis_time * 1000,
            trust_decision=trust_decision_str
        )
        
    def run_all(self, scenarios: List[EvaluationScenario]) -> List[EvaluationResult]:
        return [self.run_scenario(s) for s in scenarios]
