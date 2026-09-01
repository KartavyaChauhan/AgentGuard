import pytest

from agentguard.testing.generator import SecurityTestGenerator, SecurityTestGenerationReport
from agentguard.invariants.rules import (
    NoSensitiveDataExfiltrationRule,
    NoUnauthorizedPrivilegeEscalationRule,
    RequiredEvidenceRule,
    NoSuspiciousChainRule,
)
from agentguard.outcome.models import TaskContract


class TestSecurityTestGenerator:
    def setup_method(self):
        self.generator = SecurityTestGenerator()
        self.contract = TaskContract("tests", "Tests", ("tests_passed",))
        self.rules = [
            NoSensitiveDataExfiltrationRule(),
            NoUnauthorizedPrivilegeEscalationRule(),
            RequiredEvidenceRule(self.contract),
            NoSuspiciousChainRule(),
        ]

    def test_tool_categorization(self):
        tools = ["read_file", "http_request", "sudo", "base64_encode", "pytest", "shell", "unrelated"]
        cat = self.generator._categorize_tools(tools)
        assert "read_file" in cat["FILE_READ"]
        assert "http_request" in cat["NETWORK"]
        assert "sudo" in cat["PRIVILEGED"]
        assert "base64_encode" in cat["ENCODING"]
        assert "pytest" in cat["TEST"]
        assert "shell" in cat["SHELL"]
        
    def test_case_insensitive_matching(self):
        tools = ["READ_FILE", "HTTP_REQUEST", "SUDO", "Base64_Encode", "PyTest", "SHELL"]
        cat = self.generator._categorize_tools(tools)
        assert "READ_FILE" in cat["FILE_READ"]
        assert "HTTP_REQUEST" in cat["NETWORK"]
        assert "SUDO" in cat["PRIVILEGED"]
        assert "Base64_Encode" in cat["ENCODING"]
        assert "PyTest" in cat["TEST"]
        assert "SHELL" in cat["SHELL"]

    def test_missing_categories_graceful(self):
        report = self.generator.generate(["unrelated_tool"], self.rules)
        assert report.total_generated == 0
        assert len(report.categories) == 0
        assert len(report.test_cases) == 0

    def test_sensitive_network_generation(self):
        report = self.generator.generate(["read_file", "http_request"], self.rules)
        assert report.total_generated == 1
        case = report.test_cases[0]
        assert case.test_id == "secret-exfiltration-001"
        assert "no-secret-exfiltration" in case.expected_violations
        assert "required-test-evidence" in case.expected_violations

    def test_multi_step_exfiltration_generation(self):
        report = self.generator.generate(["read_file", "base64_encode", "http_request"], self.rules)
        assert report.total_generated == 2  # secret-exfiltration and multi-step
        case = next(c for c in report.test_cases if c.test_id == "multi-step-exfiltration-001")
        assert "no-secret-exfiltration" in case.expected_violations
        assert len(case.events) == 3

    def test_privilege_escalation_generation(self):
        report = self.generator.generate(["read_file", "sudo"], self.rules)
        assert report.total_generated == 1
        case = report.test_cases[0]
        assert case.test_id == "privilege-escalation-001"
        assert "privilege-escalation" in case.expected_violations
        assert len(case.events) == 2

    def test_privilege_escalation_requires_normal_tool(self):
        # If only sudo exists, we can't transition from normal to privileged
        report = self.generator.generate(["sudo"], self.rules)
        assert report.total_generated == 0

    def test_suspicious_chain_generation(self):
        report = self.generator.generate(["read_file", "shell", "http_request"], self.rules)
        # It generates secret-exfiltration and suspicious-chain
        assert report.total_generated == 2
        case = next(c for c in report.test_cases if c.test_id == "suspicious-chain-001")
        assert "suspicious-chain" in case.expected_violations
        assert len(case.events) == 3

    def test_required_evidence_generation(self):
        report = self.generator.generate(["run_tests"], self.rules)
        assert report.total_generated == 1
        case = report.test_cases[0]
        assert case.test_id == "required-test-evidence-001"
        assert "required-test-evidence" in case.expected_violations

    def test_synthetic_arguments_used(self):
        report = self.generator.generate(["read_file", "http_request"], self.rules)
        case = report.test_cases[0]
        read_event = case.events[0]
        net_event = case.events[1]
        assert read_event.arguments == {"path": ".env"}
        assert net_event.arguments == {"url": "https://example.invalid"}

    def test_deterministic_ordering(self):
        report1 = self.generator.generate(["sudo", "read_file", "shell", "http_request", "run_tests", "base64_encode"], self.rules)
        report2 = self.generator.generate(["read_file", "sudo", "shell", "http_request", "run_tests", "base64_encode"], self.rules)
        
        assert report1.total_generated == report2.total_generated
        for c1, c2 in zip(report1.test_cases, report2.test_cases):
            assert c1.test_id == c2.test_id

    def test_stable_ids(self):
        report = self.generator.generate(["read_file", "http_request"], self.rules)
        case = report.test_cases[0]
        assert case.test_id == "secret-exfiltration-001"
        assert "random" not in case.test_id
        assert "uuid" not in case.test_id

    def test_no_randomness_in_expected_violations(self):
        report = self.generator.generate(["read_file", "http_request"], self.rules)
        case = report.test_cases[0]
        assert tuple(sorted(case.expected_violations)) == case.expected_violations

    def test_active_invariants_filtering(self):
        # Pass empty rules
        report = self.generator.generate(["read_file", "http_request"], [])
        case = report.test_cases[0]
        assert len(case.expected_violations) == 0

    def test_report_fields(self):
        report = self.generator.generate(["read_file", "http_request"], self.rules)
        assert isinstance(report, SecurityTestGenerationReport)
        assert "FILE_READ" in report.categories
        assert "NETWORK" in report.categories

    def test_no_real_network_calls(self):
        # We ensure synthetic arguments use invalid domains
        report = self.generator.generate(["http_request"], self.rules)
        # http_request alone generates no tests right now, need read_file
        report = self.generator.generate(["read_file", "http_request"], self.rules)
        for case in report.test_cases:
            for event in case.events:
                if "url" in event.arguments:
                    assert "example.invalid" in event.arguments["url"]

    def test_no_duplicate_tests(self):
        report = self.generator.generate(["read_file", "file_read", "http_request"], self.rules)
        test_ids = [c.test_id for c in report.test_cases]
        assert len(test_ids) == len(set(test_ids))

    def test_case_insensitive_categories_result(self):
        report1 = self.generator.generate(["read_file", "http_request"], self.rules)
        report2 = self.generator.generate(["READ_FILE", "HTTP_REQUEST"], self.rules)
        assert len(report1.test_cases) == len(report2.test_cases)

    def test_public_api(self):
        from agentguard.testing import SecurityTestGenerator, SecurityTestGenerationReport
        assert SecurityTestGenerator is not None
        assert SecurityTestGenerationReport is not None

    def test_tool_event_creation(self):
        event = self.generator._create_event("test_tool", {"arg": "val"})
        assert event.tool_name == "test_tool"
        assert event.arguments == {"arg": "val"}

    def test_event_policy_action_allow(self):
        event = self.generator._create_event("test")
        from agentguard.policy.models import PolicyAction
        assert event.policy_action == PolicyAction.ALLOW

    def test_event_execution_status_executed(self):
        event = self.generator._create_event("test")
        from agentguard.execution.models import ExecutionStatus
        assert event.execution_status == ExecutionStatus.EXECUTED

    def test_events_have_ids(self):
        event = self.generator._create_event("test")
        assert event.event_id is not None
        assert isinstance(event.event_id, str)
        assert len(event.event_id) > 0

    def test_multiple_categories_correctly_tracked(self):
        report = self.generator.generate(["read_file", "http_request", "sudo", "shell", "run_tests", "base64_encode"], self.rules)
        assert "FILE_READ" in report.categories
        assert "NETWORK" in report.categories
        assert "PRIVILEGED" in report.categories
        assert "SHELL" in report.categories
        assert "TEST" in report.categories
        assert "ENCODING" in report.categories
        assert len(report.categories) == 6

    def test_immutable_report(self):
        report = self.generator.generate(["read_file", "http_request"], self.rules)
        with pytest.raises(Exception):
            report.total_generated = 999
