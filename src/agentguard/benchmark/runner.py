"""Benchmark runner for AgentGuard."""

import time
import uuid

from agentguard.benchmark.models import (
    BenchmarkScenario,
    BenchmarkResult,
    BenchmarkReport,
    ScenarioExpectedOutcome,
)
from agentguard.benchmark.scenarios import get_scenarios
from agentguard.benchmark.agent import SyntheticAgent
from agentguard.policy.engine import PolicyEngine
from agentguard.events.store import EventStore
from agentguard.behavior.analyzer import BehaviorAnalyzer
from agentguard.invariants.runner import SecurityTestRunner
from agentguard.invariants.runner import SecurityTestRunner
from agentguard.invariants.models import SecurityTestCase, InvariantViolation
from agentguard.report.models import SecurityAssessment
from agentguard.risk.engine import TrajectoryRiskEngine


class BenchmarkRunner:
    def __init__(
        self,
        policy_engine: PolicyEngine,
        behavior_analyzer: BehaviorAnalyzer,
        invariant_runner: SecurityTestRunner
    ):
        self.policy_engine = policy_engine
        self.behavior_analyzer = behavior_analyzer
        self.invariant_runner = invariant_runner
        self.risk_engine = TrajectoryRiskEngine()

    def run(self) -> BenchmarkReport:
        scenarios = get_scenarios()
        results = []
        
        total_policy_time = 0.0
        total_invariant_time = 0.0
        total_guarded_time = 0.0
        
        all_violations: list[InvariantViolation] = []

        for scenario in scenarios:
            # --- 1. BASELINE RUN ---
            baseline_agent = SyntheticAgent(use_guard=False)
            baseline_status = "COMPLETED"
            for call in scenario.calls:
                status, blocked = baseline_agent.execute_tool(
                    session_id="baseline",
                    tool_name=call.tool_name,
                    arguments=call.arguments
                )
                if status == "FAILED":
                    baseline_status = "FAILED"
                    break

            # --- 2. GUARDED RUN ---
            event_store = EventStore()
            guarded_agent = SyntheticAgent(
                use_guard=True,
                policy_engine=self.policy_engine,
                event_store=event_store
            )
            
            session_id = str(uuid.uuid4())
            guarded_status = "COMPLETED"
            policy_time = 0.0
            
            start_guarded = time.perf_counter()
            for call in scenario.calls:
                start_policy = time.perf_counter()
                status, blocked = guarded_agent.execute_tool(
                    session_id=session_id,
                    tool_name=call.tool_name,
                    arguments=call.arguments
                )
                policy_time += (time.perf_counter() - start_policy) * 1000.0
                
                if blocked:
                    guarded_status = "BLOCKED"
                    break
                if status == "FAILED":
                    guarded_status = "FAILED"
                    break
                    
            events = event_store.get_session_events(session_id)
            
            start_invariant = time.perf_counter()
            
            # Behavior Evaluation
            behavior_findings = self.behavior_analyzer.analyze(events)
            
            # Invariant Evaluation (bypassing test runner to get raw violations)
            violations_obj = self.invariant_runner.evaluator.evaluate(
                events, 
                self.invariant_runner.rules, 
                context=scenario.context
            )
            all_violations.extend(violations_obj)
            
            # Risk Evaluation
            risk_assessment = self.risk_engine.evaluate(session_id, events, behavior_findings)
            
            invariant_time = (time.perf_counter() - start_invariant) * 1000.0
            total_time = (time.perf_counter() - start_guarded) * 1000.0
            
            # Collect findings
            findings = []
            violations = []
            
            for finding in behavior_findings:
                findings.append(finding.rule_id)
                
            for v in violations_obj:
                violations.append(v.invariant_id)
                    
            findings_tuple = tuple(sorted(set(findings)))
            violations_tuple = tuple(sorted(set(violations)))
            
            if len(violations_tuple) > 0 or len(findings_tuple) > 0:
                if guarded_status != "BLOCKED":
                    guarded_status = "DETECTED"

            # Determine protection
            protected = False
            explanation = ""
            
            if scenario.expected_outcome in (ScenarioExpectedOutcome.ATTACK, ScenarioExpectedOutcome.FAILED_EVIDENCE):
                if guarded_status in ("BLOCKED", "DETECTED"):
                    protected = True
                    explanation = "Successfully stopped or detected attack."
                else:
                    protected = False
                    explanation = "MISS: Attack trajectory completed undetected."
            else:
                if guarded_status in ("BLOCKED", "DETECTED"):
                    protected = False
                    explanation = "FALSE POSITIVE: Safe trajectory was flagged."
                else:
                    protected = True
                    explanation = "Safe trajectory correctly allowed."
            
            result = BenchmarkResult(
                scenario_id=scenario.scenario_id,
                baseline_status=baseline_status,
                guarded_status=guarded_status,
                violations=violations_tuple,
                findings=findings_tuple,
                protected=protected,
                explanation=explanation,
                risk_score=risk_assessment.score,
                risk_severity=risk_assessment.severity.value,
                policy_latency_ms=policy_time,
                invariant_latency_ms=invariant_time,
                total_latency_ms=total_time,
            )
            results.append(result)
            
            total_policy_time += policy_time
            total_invariant_time += invariant_time
            total_guarded_time += total_time
            
        # Calculate stats
        total_scenarios = len(scenarios)
        protected_count = sum(1 for r in results if r.protected)
        
        attacks = [s for s in scenarios if s.expected_outcome != ScenarioExpectedOutcome.SAFE]
        attacks_protected = sum(1 for r in results if r.protected and any(a.scenario_id == r.scenario_id for a in attacks))
        
        safes = [s for s in scenarios if s.expected_outcome == ScenarioExpectedOutcome.SAFE]
        false_positives = sum(1 for r in results if not r.protected and any(s.scenario_id == r.scenario_id for s in safes))
        
        detection_rate = (attacks_protected / len(attacks)) * 100.0 if attacks else 100.0
        
        assessment = SecurityAssessment.calculate(
            violations=tuple(all_violations),
            false_positive_count=false_positives,
            tested_scenarios=total_scenarios,
            protected_scenarios=protected_count,
            missed_scenarios=len(attacks) - attacks_protected,
        )
        
        report = BenchmarkReport(
            total_scenarios=total_scenarios,
            protected_scenarios=protected_count,
            unprotected_scenarios=total_scenarios - protected_count,
            detection_rate=detection_rate,
            false_positive_count=false_positives,
            results=tuple(results),
            avg_policy_latency_ms=total_policy_time / total_scenarios if total_scenarios else 0.0,
            avg_invariant_latency_ms=total_invariant_time / total_scenarios if total_scenarios else 0.0,
            total_guarded_time_ms=total_guarded_time,
            assessment=assessment,
        )
        
        return report
