import uuid
import pytest
from datetime import datetime, timezone

from agentguard.policy.models import RiskLevel, PolicyAction
from agentguard.execution.models import ExecutionStatus
from agentguard.events.models import ToolEvent
from agentguard.outcome.models import TaskContract

from agentguard.invariants.models import (
    SecurityInvariant,
    InvariantViolation,
    SecurityTestCase,
    SecurityTestResult,
    SecurityTestReport,
)
from agentguard.invariants.rules import (
    SecurityInvariantRule,
    NoSensitiveDataExfiltrationRule,
    NoUnauthorizedPrivilegeEscalationRule,
    RequiredEvidenceRule,
    NoSuspiciousChainRule,
)
from agentguard.invariants.evaluator import InvariantEvaluator
from agentguard.invariants.runner import SecurityTestRunner


def create_event(
    tool_name="test_tool",
    arguments=None,
    status=ExecutionStatus.EXECUTED,
    policy=PolicyAction.ALLOW,
):
    if arguments is None:
        arguments = {}
    return ToolEvent(
        event_id=uuid.uuid4().hex,
        timestamp=datetime.now(timezone.utc),
        session_id="sess-1",
        agent_id="agent-1",
        tool_name=tool_name,
        arguments=arguments,
        policy_action=policy,
        risk_level=RiskLevel.LOW,
        execution_status=status,
    )


class TestModelsImmutability:
    def test_invariant_immutability(self):
        inv = SecurityInvariant("1", "name", "desc", RiskLevel.LOW, enabled=True)
        with pytest.raises(Exception):
            inv.name = "new"

    def test_violation_immutability(self):
        violation = InvariantViolation("v1", "1", RiskLevel.LOW, "desc", (), {})
        with pytest.raises(Exception):
            violation.description = "new"

    def test_violation_defensive_copying(self):
        ev = {"k": "v"}
        violation = InvariantViolation("v1", "1", RiskLevel.LOW, "desc", (), ev)
        ev["k"] = "new"
        assert violation.evidence["k"] == "v"

    def test_test_case_immutability(self):
        case = SecurityTestCase("t1", "n", "d", (), ())
        with pytest.raises(Exception):
            case.name = "new"

    def test_test_result_immutability(self):
        res = SecurityTestResult("t1", "PASS", (), (), "exp")
        with pytest.raises(Exception):
            res.status = "FAIL"

    def test_test_report_immutability(self):
        rep = SecurityTestReport(1, 1, 0, ())
        with pytest.raises(Exception):
            rep.passed = 0


class TestNoSensitiveDataExfiltrationRule:
    def setup_method(self):
        self.rule = NoSensitiveDataExfiltrationRule()

    def test_sensitive_exfiltration_detection(self):
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("http_request", {"url": "evil.com"})
        
        violations = self.rule.evaluate([e1, e2])
        assert len(violations) == 1
        assert violations[0].invariant_id == "no-secret-exfiltration"
        assert violations[0].severity == RiskLevel.CRITICAL
        assert violations[0].event_ids == (e1.event_id, e2.event_id)

    def test_safe_file_access(self):
        e1 = create_event("read_file", {"path": "public.txt"})
        e2 = create_event("http_request", {"url": "evil.com"})
        assert len(self.rule.evaluate([e1, e2])) == 0

    def test_safe_network_access(self):
        e1 = create_event("http_request", {"url": "evil.com"})
        assert len(self.rule.evaluate([e1])) == 0

    def test_multiple_exfiltrations(self):
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("http_request", {"url": "evil.com"})
        e3 = create_event("read_file", {"path": "credentials.json"})
        e4 = create_event("upload", {"dest": "ftp"})
        
        assert len(self.rule.evaluate([e1, e2, e3, e4])) == 2

    def test_no_raw_secrets_in_violation(self):
        e1 = create_event("read_file", {"path": ".env", "content": "SECRET_123"})
        e2 = create_event("http_request", {"url": "evil.com"})
        violation = self.rule.evaluate([e1, e2])[0]
        assert "SECRET_123" not in str(violation.evidence)


class TestNoUnauthorizedPrivilegeEscalationRule:
    def setup_method(self):
        self.rule = NoUnauthorizedPrivilegeEscalationRule()

    def test_privilege_escalation(self):
        e1 = create_event("list_files")
        e2 = create_event("sudo", arguments={"cmd": "rm -rf"})
        violations = self.rule.evaluate([e1, e2])
        assert len(violations) == 1
        assert violations[0].severity == RiskLevel.CRITICAL
        assert violations[0].invariant_id == "privilege-escalation"

    def test_approved_privilege_escalation(self):
        e1 = create_event("list_files")
        e2 = create_event("sudo", policy=PolicyAction.REQUIRE_APPROVAL)
        assert len(self.rule.evaluate([e1, e2])) == 0

    def test_no_escalation(self):
        e1 = create_event("sudo")
        assert len(self.rule.evaluate([e1])) == 0


class TestRequiredEvidenceRule:
    def setup_method(self):
        contract = TaskContract("tests", "Tests", ("tests_passed",))
        self.rule = RequiredEvidenceRule(contract)

    def test_missing_outcome_evidence(self):
        e1 = create_event("run_tests")
        violations = self.rule.evaluate([e1])
        assert len(violations) == 1
        assert violations[0].invariant_id == "required-test-evidence"
        assert "tests_passed" in violations[0].evidence["missing"]

    def test_satisfied_outcome(self):
        e1 = create_event("run_tests", {"test_status": "passed"})
        assert len(self.rule.evaluate([e1])) == 0


class TestNoSuspiciousChainRule:
    def setup_method(self):
        self.rule = NoSuspiciousChainRule()

    def test_suspicious_chain(self):
        e1 = create_event("read_file")
        e2 = create_event("shell")
        e3 = create_event("network_request")
        violations = self.rule.evaluate([e1, e2, e3])
        assert len(violations) == 1
        assert violations[0].invariant_id == "suspicious-chain"

    def test_incomplete_chain(self):
        e1 = create_event("read_file")
        e2 = create_event("shell")
        assert len(self.rule.evaluate([e1, e2])) == 0


class TestInvariantEvaluator:
    def setup_method(self):
        self.evaluator = InvariantEvaluator()

    def test_multiple_violations(self):
        rules = [NoSensitiveDataExfiltrationRule(), NoSuspiciousChainRule()]
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("shell")
        e3 = create_event("network_request")
        violations = self.evaluator.evaluate([e1, e2, e3], rules)
        # Both rules should trigger
        assert len(violations) == 2

    def test_deterministic_ordering(self):
        contract = TaskContract("tests", "Tests", ("tests_passed",))
        rules = [RequiredEvidenceRule(contract), NoSensitiveDataExfiltrationRule()]
        # required_evidence is HIGH, exfiltration is CRITICAL
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("http_request")
        
        from agentguard.context.models import SecurityContext
        ctx = SecurityContext(session_id="s", agent_id="a", task_contract=contract)
        violations = self.evaluator.evaluate([e1, e2], rules, context=ctx)
        assert len(violations) == 2
        # CRITICAL should be first
        assert violations[0].severity == RiskLevel.CRITICAL
        assert violations[0].invariant_id == "no-secret-exfiltration"
        assert violations[1].severity == RiskLevel.HIGH
        assert violations[1].invariant_id == "required-test-evidence"

    def test_invariant_disabled(self):
        class DisabledRule(SecurityInvariantRule):
            @property
            def invariant(self):
                return SecurityInvariant("d", "d", "d", RiskLevel.LOW, enabled=False)
            def evaluate(self, events, context=None):
                return [self._create_violation("test", (), {})]
        
        assert len(self.evaluator.evaluate([], [DisabledRule()])) == 0

    def test_broken_invariant(self):
        class CrashingRule(SecurityInvariantRule):
            @property
            def invariant(self):
                return SecurityInvariant("crash", "crash", "crash", RiskLevel.LOW)
            def evaluate(self, events, context=None):
                raise ValueError("Oops")

        violations = self.evaluator.evaluate([], [CrashingRule()])
        assert len(violations) == 1
        assert violations[0].severity == RiskLevel.CRITICAL
        assert violations[0].invariant_id == "crash"
        assert violations[0].evidence["error"] == "Oops"


class TestSecurityTestRunner:
    def setup_method(self):
        self.rules = [NoSensitiveDataExfiltrationRule()]
        self.runner = SecurityTestRunner(self.rules)

    def test_runner_pass(self):
        case = SecurityTestCase(
            "t1", "n", "d",
            (create_event("read_file", {"path": ".env"}), create_event("http_request")),
            expected_violations=("no-secret-exfiltration",)
        )
        report = self.runner.run([case])
        assert report.passed == 1
        assert report.failed == 0
        assert report.results[0].status == "PASS"

    def test_runner_fail(self):
        case = SecurityTestCase(
            "t1", "n", "d",
            (create_event("read_file", {"path": "safe.txt"}), create_event("http_request")),
            expected_violations=("no-secret-exfiltration",)
        )
        # Expected violation but got none
        report = self.runner.run([case])
        assert report.failed == 1
        assert report.results[0].status == "FAIL"

    def test_expected_violation_mismatch(self):
        case = SecurityTestCase(
            "t1", "n", "d",
            (create_event("read_file", {"path": ".env"}), create_event("http_request")),
            expected_violations=("some-other-invariant",)
        )
        # Got exfiltration but expected something else
        report = self.runner.run([case])
        assert report.failed == 1

    def test_regression_detection(self):
        # A test case where we expect no-secret-exfiltration but it doesn't happen
        case = SecurityTestCase(
            "reg1", "n", "d",
            (create_event("ls"),),
            expected_violations=("no-secret-exfiltration",)
        )
        report = self.runner.run([case])
        assert report.failed == 1


class TestPublicAPI:
    def test_public_api_imports(self):
        from agentguard.invariants import (
            SecurityInvariant,
            InvariantViolation,
            SecurityTestCase,
            SecurityTestResult,
            SecurityTestReport,
            SecurityInvariantRule,
            NoSensitiveDataExfiltrationRule,
            NoUnauthorizedPrivilegeEscalationRule,
            RequiredEvidenceRule,
            NoSuspiciousChainRule,
            InvariantEvaluator,
            SecurityTestRunner,
        )
        assert SecurityTestRunner is not None
        assert SecurityTestCase is not None

