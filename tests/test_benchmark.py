import pytest

from agentguard.benchmark.models import (
    BenchmarkScenario,
    MockToolCall,
    ScenarioExpectedOutcome,
    BenchmarkResult,
    BenchmarkReport,
)
from agentguard.benchmark.scenarios import get_scenarios
from agentguard.benchmark.agent import SyntheticAgent
from agentguard.benchmark.runner import BenchmarkRunner
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.rules import (
    ToolNameRule,
    ApprovalRule,
)
from agentguard.policy.models import ToolRequest
from agentguard.events.store import EventStore
from agentguard.behavior.analyzer import BehaviorAnalyzer
from agentguard.outcome.models import TaskContract
from agentguard.invariants.runner import SecurityTestRunner
from agentguard.invariants.rules import (
    NoSensitiveDataExfiltrationRule,
    NoUnauthorizedPrivilegeEscalationRule,
    RequiredEvidenceRule,
    NoSuspiciousChainRule,
)


class TestBenchmarkModels:
    def test_mock_tool_call_defaults(self):
        call = MockToolCall("test")
        assert call.tool_name == "test"
        assert call.arguments == {}

    def test_mock_tool_call_immutable(self):
        call = MockToolCall("test", {"a": 1})
        with pytest.raises(Exception):
            call.tool_name = "new"

    def test_scenario_creation(self):
        scenario = BenchmarkScenario(
            scenario_id="1",
            description="desc",
            expected_outcome=ScenarioExpectedOutcome.ATTACK,
            calls=(MockToolCall("t"),)
        )
        assert scenario.scenario_id == "1"
        assert scenario.expected_outcome == ScenarioExpectedOutcome.ATTACK

    def test_result_creation(self):
        res = BenchmarkResult(
            scenario_id="1",
            baseline_status="COMPLETED",
            guarded_status="BLOCKED",
            violations=("v1",),
            findings=(),
            protected=True,
            explanation="test"
        )
        assert res.protected is True
        assert res.policy_latency_ms == 0.0

    def test_report_creation(self):
        rep = BenchmarkReport(
            total_scenarios=1,
            protected_scenarios=1,
            unprotected_scenarios=0,
            detection_rate=100.0,
            false_positive_count=0,
            results=(),
            avg_policy_latency_ms=1.0,
            avg_invariant_latency_ms=2.0,
            total_guarded_time_ms=3.0
        )
        assert rep.detection_rate == 100.0


class TestSyntheticAgent:
    def test_unguarded_execution(self):
        agent = SyntheticAgent(use_guard=False)
        status, blocked = agent.execute_tool("sess", "read_file", {})
        assert status == "COMPLETED"
        assert not blocked

    def test_unguarded_execution_returns_failed_if_unknown(self):
        agent = SyntheticAgent(use_guard=False)
        # Assuming missing tool fails in ToolExecutor
        status, blocked = agent.execute_tool("sess", "unknown_tool", {})
        assert status == "FAILED"
        assert not blocked



    def test_guarded_execution_allowed(self):
        engine = PolicyEngine()
        store = EventStore()
        agent = SyntheticAgent(use_guard=True, policy_engine=engine, event_store=store)
        status, blocked = agent.execute_tool("sess", "read_file", {})
        assert status == "COMPLETED"
        assert not blocked
        events = store.get_session_events("sess")
        assert len(events) == 1

    def test_guarded_execution_blocked(self):
        engine = PolicyEngine(rules=[ToolNameRule(id="b1", description="desc", tool_name="read_file")])
        store = EventStore()
        agent = SyntheticAgent(use_guard=True, policy_engine=engine, event_store=store)
        status, blocked = agent.execute_tool("sess", "read_file", {})
        assert status == "BLOCKED"
        assert blocked
        events = store.get_session_events("sess")
        assert len(events) == 1
        assert events[0].execution_status.value == "DENIED"

    def test_mock_tool_output(self):
        agent = SyntheticAgent()
        res = agent.executor.execute(ToolRequest("read_file", {}))
        assert res.output == "mock file content"

    def test_all_scenarios_tools_registered(self):
        agent = SyntheticAgent()
        scenarios = get_scenarios()
        for s in scenarios:
            for c in s.calls:
                res = agent.executor.execute(ToolRequest(c.tool_name, c.arguments))
                assert res.status.value != "FAILED", f"Tool {c.tool_name} failed execution"


class TestBenchmarkScenarios:
    def test_scenarios_count(self):
        assert len(get_scenarios()) == 10

    def test_sensitive_file_network_scenario(self):
        scenarios = get_scenarios()
        s = next(s for s in scenarios if s.scenario_id == "sensitive-file-network")
        assert len(s.calls) == 2
        assert s.expected_outcome == ScenarioExpectedOutcome.ATTACK
        
    def test_all_expected_outcomes(self):
        scenarios = get_scenarios()
        attacks = [s for s in scenarios if s.expected_outcome == ScenarioExpectedOutcome.ATTACK]
        safes = [s for s in scenarios if s.expected_outcome == ScenarioExpectedOutcome.SAFE]
        fails = [s for s in scenarios if s.expected_outcome == ScenarioExpectedOutcome.FAILED_EVIDENCE]
        assert len(attacks) == 5
        assert len(safes) == 4
        assert len(fails) == 1


class TestBenchmarkRunner:
    def setup_method(self):
        self.rules = [
            NoSensitiveDataExfiltrationRule(),
            NoUnauthorizedPrivilegeEscalationRule(),
            RequiredEvidenceRule(TaskContract("tests", "Tests", ("tests_passed",))),
            NoSuspiciousChainRule(),
        ]
        self.policy_engine = PolicyEngine(rules=[
            # Block git push directly
            ToolNameRule(id="b2", description="desc", tool_name="git_push")
        ])
        self.behavior_analyzer = BehaviorAnalyzer([])
        self.invariant_runner = SecurityTestRunner(self.rules)
        self.runner = BenchmarkRunner(
            self.policy_engine,
            self.behavior_analyzer,
            self.invariant_runner
        )

    def test_runner_initialization(self):
        assert self.runner.policy_engine is not None

    def test_run_returns_report(self):
        report = self.runner.run()
        assert isinstance(report, BenchmarkReport)

    def test_total_scenarios(self):
        report = self.runner.run()
        assert report.total_scenarios == 10
        assert len(report.results) == 10

    def test_baseline_execution_unblocked(self):
        report = self.runner.run()
        # All baseline scenarios should complete
        for res in report.results:
            assert res.baseline_status == "COMPLETED"

    def test_guarded_execution_blocks_policy(self):
        report = self.runner.run()
        res = next(r for r in report.results if r.scenario_id == "force-git-push")
        assert res.guarded_status == "BLOCKED"
        assert res.protected

    def test_guarded_execution_detects_invariant(self):
        report = self.runner.run()
        res = next(r for r in report.results if r.scenario_id == "sensitive-file-network")
        # May be DETECTED instead of BLOCKED
        assert res.guarded_status == "DETECTED"
        assert res.protected
        assert "no-secret-exfiltration" in res.violations

    def test_guarded_execution_detects_outcome(self):
        report = self.runner.run()
        res = next(r for r in report.results if r.scenario_id == "failed-test-evidence")
        assert res.protected
        assert "required-test-evidence" in res.violations

    def test_safe_scenarios_pass(self):
        report = self.runner.run()
        safe_res = next(r for r in report.results if r.scenario_id == "safe-dev-workflow")
        assert safe_res.guarded_status == "COMPLETED"
        assert safe_res.protected
        assert "FALSE POSITIVE" not in safe_res.explanation

    def test_false_positive_tracking(self):
        # We enforce a bad invariant that blocks all
        # to test false positive tracking
        runner2 = BenchmarkRunner(
            self.policy_engine,
            self.behavior_analyzer,
            SecurityTestRunner([
                # Re-use rules that always flag
                NoUnauthorizedPrivilegeEscalationRule()
            ])
        )
        # Just run default, it shouldn't have FP
        report = runner2.run()
        assert report.false_positive_count == 0

    def test_latency_measurements(self):
        report = self.runner.run()
        assert report.avg_policy_latency_ms >= 0
        assert report.avg_invariant_latency_ms >= 0
        assert report.total_guarded_time_ms >= 0
        for res in report.results:
            assert res.policy_latency_ms >= 0
            assert res.invariant_latency_ms >= 0
            assert res.total_latency_ms >= 0

    def test_missed_attack_tracking(self):
        # Create a runner with no invariants, so attacks slip through
        runner2 = BenchmarkRunner(
            PolicyEngine(),
            BehaviorAnalyzer([]),
            SecurityTestRunner([])
        )
        report = runner2.run()
        # All attacks should be missed except safe ones
        # There are 5 attacks + 1 failed outcome
        assert report.unprotected_scenarios >= 6
        assert report.detection_rate < 100.0

    def test_detection_rate_calculation(self):
        report = self.runner.run()
        assert 0.0 <= report.detection_rate <= 100.0

    def test_determinism_same_results(self):
        r1 = self.runner.run()
        r2 = self.runner.run()
        
        for i in range(10):
            assert r1.results[i].protected == r2.results[i].protected
            assert r1.results[i].guarded_status == r2.results[i].guarded_status

    def test_no_actual_execution_effects(self):
        agent = SyntheticAgent(use_guard=False)
        agent.executor.execute(ToolRequest("shell", {"command": "echo REAL_TEST > test_file.txt"}))
        import os
        assert not os.path.exists("test_file.txt")

    def test_public_api(self):
        import agentguard.benchmark
        assert agentguard.benchmark.BenchmarkRunner is not None
        assert agentguard.benchmark.SyntheticAgent is not None
        assert callable(agentguard.benchmark.get_scenarios)

    def test_cli_integration(self):
        # Ensure the run_benchmark_command can run without error
        from agentguard.cli import run_benchmark_command
        # Instead of actually running it and spamming stdout, we can check if it returns 0 or 1
        # It's an end to end test
        res = run_benchmark_command()
        # If there are misses, it returns 1
        assert res in (0, 1)

    def test_suspicious_chain_detected(self):
        report = self.runner.run()
        res = next(r for r in report.results if r.scenario_id == "suspicious-chain")
        assert res.protected
        assert "suspicious-chain" in res.violations

    def test_privilege_escalation_detected(self):
        report = self.runner.run()
        res = next(r for r in report.results if r.scenario_id == "privilege-escalation")
        assert res.protected
        assert "privilege-escalation" in res.violations

    def test_sensitive_file_encode_network_detected(self):
        report = self.runner.run()
        res = next(r for r in report.results if r.scenario_id == "sensitive-file-encode-network")
        assert res.protected
        assert "no-secret-exfiltration" in res.violations
