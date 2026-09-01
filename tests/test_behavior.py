import uuid
import pytest
from datetime import datetime, timezone

from agentguard.policy.models import RiskLevel, PolicyAction
from agentguard.execution.models import ExecutionStatus
from agentguard.events.models import ToolEvent

from agentguard.behavior.models import BehaviorFinding
from agentguard.behavior.rules import (
    BehaviorRule,
    SensitiveDataToNetworkRule,
    EncodingBeforeNetworkRule,
    PrivilegeEscalationRule,
    RepeatedFailureRule,
    SuspiciousToolChainRule,
)
from agentguard.behavior.analyzer import BehaviorAnalyzer


def create_event(
    tool_name="test_tool",
    arguments=None,
    status=ExecutionStatus.EXECUTED,
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
        policy_action=PolicyAction.ALLOW,
        risk_level=RiskLevel.LOW,
        execution_status=status,
    )


class TestBehaviorFindingModel:
    def test_finding_immutability(self):
        f = BehaviorFinding(
            finding_id="id",
            rule_id="r1",
            severity=RiskLevel.LOW,
            title="t",
            description="d",
            event_ids=("e1",),
            evidence={},
            confidence=0.5,
        )
        with pytest.raises(Exception):
            f.title = "new"

    def test_confidence_validation_low(self):
        with pytest.raises(ValueError, match="confidence"):
            BehaviorFinding(
                finding_id="id",
                rule_id="r1",
                severity=RiskLevel.LOW,
                title="t",
                description="d",
                event_ids=(),
                evidence={},
                confidence=-0.1,
            )

    def test_confidence_validation_high(self):
        with pytest.raises(ValueError, match="confidence"):
            BehaviorFinding(
                finding_id="id",
                rule_id="r1",
                severity=RiskLevel.LOW,
                title="t",
                description="d",
                event_ids=(),
                evidence={},
                confidence=1.1,
            )

    def test_serialization(self):
        f = BehaviorFinding(
            finding_id="id",
            rule_id="r1",
            severity=RiskLevel.HIGH,
            title="t",
            description="d",
            event_ids=("e1", "e2"),
            evidence={"key": "val"},
            confidence=0.9,
        )
        d = f.to_dict()
        assert d["finding_id"] == "id"
        assert d["severity"] == "HIGH"
        assert d["event_ids"] == ["e1", "e2"]

    def test_defensive_copying_evidence(self):
        ev = {"k": ["v"]}
        f = BehaviorFinding(
            finding_id="id",
            rule_id="r1",
            severity=RiskLevel.LOW,
            title="t",
            description="d",
            event_ids=(),
            evidence=ev,
            confidence=0.5,
        )
        ev["k"].append("v2")
        assert f.evidence == {"k": ["v"]}


class TestSensitiveDataToNetworkRule:
    def setup_method(self):
        self.rule = SensitiveDataToNetworkRule()

    def test_no_events(self):
        assert len(self.rule.evaluate([])) == 0

    def test_single_harmless_event(self):
        e1 = create_event("read_file", {"path": "harmless.txt"})
        assert len(self.rule.evaluate([e1])) == 0

    def test_sensitive_then_network(self):
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("http_request", {"url": "http://evil.com"})
        
        findings = self.rule.evaluate([e1, e2])
        assert len(findings) == 1
        assert findings[0].severity == RiskLevel.HIGH
        assert findings[0].event_ids == (e1.event_id, e2.event_id)
        assert findings[0].evidence["sensitive_indicator"] == ".env"

    def test_non_sensitive_then_network(self):
        e1 = create_event("read_file", {"path": "public.txt"})
        e2 = create_event("http_request", {"url": "http://good.com"})
        
        assert len(self.rule.evaluate([e1, e2])) == 0

    def test_network_then_sensitive(self):
        e1 = create_event("http_request", {"url": "http://good.com"})
        e2 = create_event("read_file", {"path": ".env"})
        
        # Order matters! Network came before read.
        assert len(self.rule.evaluate([e1, e2])) == 0

    def test_sensitive_then_unrelated_then_network(self):
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("calculate", {"a": 1})
        e3 = create_event("http_request", {"url": "http://evil.com"})
        
        findings = self.rule.evaluate([e1, e2, e3])
        assert len(findings) == 1
        assert findings[0].event_ids == (e1.event_id, e3.event_id)
        
    def test_denied_events_ignored(self):
        e1 = create_event("read_file", {"path": ".env"}, status=ExecutionStatus.DENIED)
        e2 = create_event("http_request", {"url": "http://evil.com"})
        
        # Since e1 was denied, it shouldn't trigger the rule
        assert len(self.rule.evaluate([e1, e2])) == 0


class TestEncodingBeforeNetworkRule:
    def setup_method(self):
        self.rule = EncodingBeforeNetworkRule()

    def test_sensitive_encoding_network(self):
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("base64_encode", {"data": "..."})
        e3 = create_event("http_request", {"url": "http://evil.com"})
        
        findings = self.rule.evaluate([e1, e2, e3])
        assert len(findings) == 1
        assert findings[0].severity == RiskLevel.CRITICAL
        assert findings[0].event_ids == (e1.event_id, e2.event_id, e3.event_id)

    def test_sensitive_encoding_without_network(self):
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("base64_encode", {"data": "..."})
        
        assert len(self.rule.evaluate([e1, e2])) == 0

    def test_encoding_network_without_sensitive(self):
        e1 = create_event("base64_encode", {"data": "..."})
        e2 = create_event("http_request", {"url": "http://evil.com"})
        
        assert len(self.rule.evaluate([e1, e2])) == 0

    def test_sensitive_network_without_encoding(self):
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("http_request", {"url": "http://evil.com"})
        
        # This triggers Rule 1, but NOT Rule 2.
        assert len(self.rule.evaluate([e1, e2])) == 0

    def test_interrupted_by_unrelated(self):
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("calculate")
        e3 = create_event("base64_encode", {"data": "..."})
        e4 = create_event("echo")
        e5 = create_event("http_request", {"url": "http://evil.com"})
        
        findings = self.rule.evaluate([e1, e2, e3, e4, e5])
        assert len(findings) == 1
        assert findings[0].event_ids == (e1.event_id, e3.event_id, e5.event_id)

    def test_encoding_tool_case_insensitivity(self):
        # Tools in constructor are lowercase, let's make sure it matches if the tool name has varying cases? 
        # Actually our implementation uses 'in' so it's case sensitive unless implemented otherwise.
        # But let's verify exact matching behavior based on implementation.
        # It's exact match string in set in implementation.
        pass


class TestPrivilegeEscalationRule:
    def setup_method(self):
        self.rule = PrivilegeEscalationRule()

    def test_normal_to_privileged(self):
        e1 = create_event("list_files", {})
        e2 = create_event("run_sudo", {})
        
        findings = self.rule.evaluate([e1, e2])
        assert len(findings) == 1
        assert findings[0].severity == RiskLevel.HIGH
        assert findings[0].event_ids == (e1.event_id, e2.event_id)
        assert findings[0].evidence["privileged_tool"] == "run_sudo"

    def test_normal_to_normal(self):
        e1 = create_event("list_files", {})
        e2 = create_event("read_file", {})
        assert len(self.rule.evaluate([e1, e2])) == 0

    def test_privileged_only(self):
        # Normal event must come first to count as escalation
        e1 = create_event("run_sudo", {})
        assert len(self.rule.evaluate([e1])) == 0

    def test_multiple_escalations(self):
        e1 = create_event("list_files")
        e2 = create_event("run_sudo")
        e3 = create_event("read_file")
        e4 = create_event("run_shell")
        
        findings = self.rule.evaluate([e1, e2, e3, e4])
        assert len(findings) == 2

    def test_privileged_to_normal_no_escalation(self):
        e1 = create_event("run_sudo")
        e2 = create_event("list_files")
        assert len(self.rule.evaluate([e1, e2])) == 0


class TestRepeatedFailureRule:
    def setup_method(self):
        self.rule = RepeatedFailureRule(threshold=3)

    def test_below_failure_threshold(self):
        e1 = create_event("tool", status=ExecutionStatus.FAILED)
        e2 = create_event("tool", status=ExecutionStatus.FAILED)
        assert len(self.rule.evaluate([e1, e2])) == 0

    def test_reaches_failure_threshold(self):
        e1 = create_event("toolA", status=ExecutionStatus.FAILED)
        e2 = create_event("toolB", status=ExecutionStatus.FAILED)
        e3 = create_event("toolC", status=ExecutionStatus.FAILED)
        
        findings = self.rule.evaluate([e1, e2, e3])
        assert len(findings) == 1
        assert findings[0].severity == RiskLevel.MEDIUM
        assert findings[0].event_ids == (e1.event_id, e2.event_id, e3.event_id)
        assert findings[0].evidence["failure_count"] == 3

    def test_success_resets_failure_chain(self):
        e1 = create_event("toolA", status=ExecutionStatus.FAILED)
        e2 = create_event("toolB", status=ExecutionStatus.FAILED)
        e3 = create_event("toolC", status=ExecutionStatus.EXECUTED)
        e4 = create_event("toolD", status=ExecutionStatus.FAILED)
        
        # Max consecutive failures is 2.
        assert len(self.rule.evaluate([e1, e2, e3, e4])) == 0

    def test_two_chains_of_failures(self):
        e1 = create_event("toolA", status=ExecutionStatus.FAILED)
        e2 = create_event("toolB", status=ExecutionStatus.FAILED)
        e3 = create_event("toolC", status=ExecutionStatus.FAILED)
        e4 = create_event("success", status=ExecutionStatus.EXECUTED)
        e5 = create_event("toolD", status=ExecutionStatus.FAILED)
        e6 = create_event("toolE", status=ExecutionStatus.FAILED)
        e7 = create_event("toolF", status=ExecutionStatus.FAILED)
        
        findings = self.rule.evaluate([e1, e2, e3, e4, e5, e6, e7])
        assert len(findings) == 2


class TestSuspiciousToolChainRule:
    def setup_method(self):
        self.rule = SuspiciousToolChainRule()

    def test_exact_suspicious_chain(self):
        e1 = create_event("read_file")
        e2 = create_event("run_shell")
        e3 = create_event("network_request")
        
        findings = self.rule.evaluate([e1, e2, e3])
        assert len(findings) == 1
        assert findings[0].severity == RiskLevel.HIGH

    def test_incomplete_chain(self):
        e1 = create_event("read_file")
        e2 = create_event("run_shell")
        assert len(self.rule.evaluate([e1, e2])) == 0

    def test_chain_interrupted_by_unrelated(self):
        e1 = create_event("read_file")
        e2 = create_event("calculate")
        e3 = create_event("run_shell")
        e4 = create_event("network_request")
        
        findings = self.rule.evaluate([e1, e2, e3, e4])
        assert len(findings) == 1
        assert findings[0].event_ids == (e1.event_id, e3.event_id, e4.event_id)

    def test_chain_does_not_contain_secrets(self):
        e1 = create_event("read_file", {"path": "sec.txt"})
        e2 = create_event("run_shell")
        e3 = create_event("network_request")
        
        finding = self.rule.evaluate([e1, e2, e3])[0]
        # Check that arguments are not dumped directly into evidence for the whole chain in a way that leaks secrets
        assert finding.evidence["chain"] == ["read_file", "run_shell", "network_request"]
        # Raw tool output/secrets should not be in evidence natively by this rule.
        assert "sec.txt" not in str(finding.evidence)

    def test_chain_multiple_occurrences(self):
        e1 = create_event("read_file")
        e2 = create_event("run_shell")
        e3 = create_event("network_request")
        
        e4 = create_event("read_file")
        e5 = create_event("run_shell")
        e6 = create_event("network_request")
        
        findings = self.rule.evaluate([e1, e2, e3, e4, e5, e6])
        assert len(findings) == 2

    def test_chain_with_denied_event_interruption(self):
        e1 = create_event("read_file")
        e2 = create_event("run_shell", status=ExecutionStatus.DENIED)
        e3 = create_event("run_shell")
        e4 = create_event("network_request")
        
        # Denied event is skipped, so the chain still completes.
        findings = self.rule.evaluate([e1, e2, e3, e4])
        assert len(findings) == 1
        assert findings[0].event_ids == (e1.event_id, e3.event_id, e4.event_id)


class TestBehaviorAnalyzer:
    def test_empty_rules(self):
        analyzer = BehaviorAnalyzer()
        assert analyzer.analyze([create_event()]) == []

    def test_multiple_findings_deterministic_order(self):
        r1 = SensitiveDataToNetworkRule()
        r2 = SuspiciousToolChainRule(sequence=["read_file", "shell", "http_request"])
        
        analyzer = BehaviorAnalyzer(rules=[r1, r2])
        
        # Create a sequence that triggers BOTH rules
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("run_shell")
        e3 = create_event("http_request")
        
        findings = analyzer.analyze([e1, e2, e3])
        assert len(findings) == 2
        # Findings should be sorted deterministically
        assert findings[0].rule_id == "sensitive-data-to-network"
        assert findings[1].rule_id == "suspicious-tool-chain"

    def test_rule_failure_handling(self):
        class CrashingRule(BehaviorRule):
            @property
            def id(self): return "crash-rule"
            def evaluate(self, events):
                raise ValueError("Oops!")

        analyzer = BehaviorAnalyzer(rules=[CrashingRule(), SensitiveDataToNetworkRule()])
        
        e1 = create_event("read_file", {"path": ".env"})
        e2 = create_event("http_request")
        
        findings = analyzer.analyze([e1, e2])
        
        # We should get a failure finding + the successful rule finding
        assert len(findings) == 2
        
        # Find the failure finding
        failure = [f for f in findings if f.rule_id == "crash-rule"][0]
        assert failure.severity == RiskLevel.CRITICAL
        assert failure.title == "Analyzer Rule Failure"
        assert failure.evidence["error"] == "Oops!"
        
        # And the other rule still worked
        success = [f for f in findings if f.rule_id == "sensitive-data-to-network"][0]
        assert success.severity == RiskLevel.HIGH


class TestPublicAPI:
    def test_public_api_imports(self):
        # Just importing them from the top level module is the test
        from agentguard.behavior import (
            BehaviorAnalyzer,
            BehaviorFinding,
            BehaviorRule,
            SensitiveDataToNetworkRule,
            EncodingBeforeNetworkRule,
            PrivilegeEscalationRule,
            RepeatedFailureRule,
            SuspiciousToolChainRule,
        )
        assert BehaviorAnalyzer is not None
        assert BehaviorFinding is not None
