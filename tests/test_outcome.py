import uuid
import pytest
from datetime import datetime, timezone

from agentguard.policy.models import RiskLevel, PolicyAction
from agentguard.execution.models import ExecutionStatus
from agentguard.events.models import ToolEvent

from agentguard.outcome.models import (
    TaskContract,
    EvidenceItem,
    OutcomeAssessment,
    EvidenceStatus,
)
from agentguard.outcome.evaluator import EvidenceEvaluator


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


class TestModelsImmutability:
    def test_task_contract_immutability(self):
        contract = TaskContract(
            contract_id="c1",
            task_name="t1",
            required_evidence=("e1",)
        )
        with pytest.raises(Exception):
            contract.task_name = "t2"

    def test_task_contract_defensive_copying(self):
        meta = {"key": "val"}
        contract = TaskContract(
            contract_id="c1",
            task_name="t1",
            required_evidence=("e1",),
            metadata=meta
        )
        meta["key"] = "newval"
        assert contract.metadata["key"] == "val"

    def test_evidence_item_immutability(self):
        item = EvidenceItem(
            evidence_id="1",
            evidence_type="type",
            event_id="e1",
            timestamp=datetime.now(timezone.utc),
            status=EvidenceStatus.OBSERVED,
            details={}
        )
        with pytest.raises(Exception):
            item.evidence_type = "newtype"

    def test_evidence_item_defensive_copying(self):
        details = {"key": "val"}
        item = EvidenceItem(
            evidence_id="1",
            evidence_type="type",
            event_id="e1",
            timestamp=datetime.now(timezone.utc),
            status=EvidenceStatus.OBSERVED,
            details=details
        )
        details["key"] = "newval"
        assert item.details["key"] == "val"

    def test_outcome_assessment_immutability(self):
        assessment = OutcomeAssessment(
            contract_id="c1",
            satisfied=True,
            missing_evidence=(),
            observed_evidence=(),
            failed_evidence=(),
            evidence_ids=(),
            explanation="text"
        )
        with pytest.raises(Exception):
            assessment.satisfied = False


class TestEvidenceEvaluator:
    def setup_method(self):
        self.evaluator = EvidenceEvaluator()

    def test_empty_event_history(self):
        contract = TaskContract("c1", "Task", ("tests_executed",))
        result = self.evaluator.evaluate(contract, [])
        assert not result.satisfied
        assert "tests_executed" in result.missing_evidence
        assert "Missing required evidence: tests_executed" in result.explanation

    def test_required_evidence_missing(self):
        contract = TaskContract("c1", "Task", ("tests_executed", "tests_passed"))
        e1 = create_event("run_tests")
        result = self.evaluator.evaluate(contract, [e1])
        assert not result.satisfied
        assert "tests_executed" not in result.missing_evidence # It WAS observed
        assert "tests_passed" in result.missing_evidence       # But this wasn't

    def test_tests_executed_detected(self):
        contract = TaskContract("c1", "Task", ("tests_executed",))
        e1 = create_event("run_tests")
        result = self.evaluator.evaluate(contract, [e1])
        assert result.satisfied
        assert "tests_executed" in result.observed_evidence

    def test_tests_passed_detected_from_explicit_success_metadata(self):
        contract = TaskContract("c1", "Task", ("tests_passed",))
        e1 = create_event("run_tests", {"test_status": "passed"})
        result = self.evaluator.evaluate(contract, [e1])
        assert result.satisfied
        assert "tests_passed" in result.observed_evidence

    def test_tests_passed_not_inferred_from_executed(self):
        contract = TaskContract("c1", "Task", ("tests_passed",))
        e1 = create_event("run_tests", {}, status=ExecutionStatus.EXECUTED)
        result = self.evaluator.evaluate(contract, [e1])
        assert not result.satisfied
        assert "tests_passed" in result.missing_evidence

    def test_failed_test_evidence(self):
        contract = TaskContract("c1", "Task", ("tests_passed",))
        e1 = create_event("run_tests", {"test_status": "failed"})
        result = self.evaluator.evaluate(contract, [e1])
        assert not result.satisfied
        assert "tests_passed" in result.failed_evidence
        assert "Failed evidence observed" in result.explanation

    def test_file_modified_detected(self):
        contract = TaskContract("c1", "Task", ("file_modified",))
        e1 = create_event("edit_file", {"path": "main.py"})
        result = self.evaluator.evaluate(contract, [e1])
        assert result.satisfied
        assert "file_modified" in result.observed_evidence

    def test_deployment_succeeded_explicit_success(self):
        contract = TaskContract("c1", "Task", ("deployment_succeeded",))
        e1 = create_event("run_deploy", {"deploy_status": "success"})
        result = self.evaluator.evaluate(contract, [e1])
        assert result.satisfied
        assert "deployment_succeeded" in result.observed_evidence

    def test_deployment_execution_without_success_evidence(self):
        contract = TaskContract("c1", "Task", ("deployment_succeeded",))
        e1 = create_event("run_deploy", {}, status=ExecutionStatus.EXECUTED)
        result = self.evaluator.evaluate(contract, [e1])
        assert not result.satisfied
        assert "deployment_succeeded" in result.missing_evidence

    def test_optional_evidence(self):
        contract = TaskContract(
            "c1", "Task",
            required_evidence=("file_modified",),
            optional_evidence=("tests_executed",)
        )
        e1 = create_event("edit_file", {"path": "main.py"})
        result = self.evaluator.evaluate(contract, [e1])
        assert result.satisfied  # tests_executed is missing but optional
        assert "file_modified" in result.observed_evidence
        assert "tests_executed" not in result.observed_evidence

    def test_multiple_required_evidence_items(self):
        contract = TaskContract("c1", "Task", ("file_modified", "tests_executed", "tests_passed"))
        e1 = create_event("edit_file", {"path": "main.py"})
        e2 = create_event("run_tests", {"test_status": "passed"})
        result = self.evaluator.evaluate(contract, [e1, e2])
        assert result.satisfied
        assert "file_modified" in result.observed_evidence
        assert "tests_executed" in result.observed_evidence
        assert "tests_passed" in result.observed_evidence

    def test_failed_evidence_blocks_satisfaction(self):
        # Even if some required evidence is there, if something failed, the task isn't truly "satisfied"
        # Wait, the rule is "satisfied = len(missing) == 0 and len(failed_types) == 0"
        contract = TaskContract("c1", "Task", ("tests_executed",))
        e1 = create_event("run_tests", {"test_status": "failed"})
        result = self.evaluator.evaluate(contract, [e1])
        # tests_executed was observed (it executed), but tests_passed failed.
        # So the task is NOT satisfied.
        assert not result.satisfied
        assert "tests_executed" in result.observed_evidence
        assert "tests_passed" in result.failed_evidence

    def test_evidence_provenance(self):
        contract = TaskContract("c1", "Task", ("tests_executed",))
        e1 = create_event("run_tests")
        items = self.evaluator._extract_evidence([e1])
        assert len(items) == 1
        assert items[0].event_id == e1.event_id

    def test_no_raw_output_in_evidence(self):
        # Even if arguments had large file contents, they shouldn't leak into evidence unless explicitly selected
        contract = TaskContract("c1", "Task", ("file_modified",))
        e1 = create_event("edit_file", {"path": "main.py", "content": "SUPER SECRET STUFF", "result": "BIG OUTPUT"})
        items = self.evaluator._extract_evidence([e1])
        
        # Details should only contain what we explicitly saved (tool_name, file_path)
        assert "SUPER SECRET STUFF" not in str(items[0].details)
        assert items[0].details == {"tool_name": "edit_file", "file_path": "main.py"}

    def test_no_secrets_in_evidence(self):
        e1 = create_event("run_deploy", {"deploy_status": "success", "api_key": "SECRET_KEY_123"})
        items = self.evaluator._extract_evidence([e1])
        assert "SECRET_KEY_123" not in str(items[0].details)

    def test_end_to_end_evaluation(self):
        contract = TaskContract(
            "c_full", "Full Deploy",
            required_evidence=("file_modified", "tests_executed", "tests_passed", "deployment_succeeded")
        )
        e1 = create_event("edit_file", {"path": "app.py"})
        e2 = create_event("run_tests", {"test_status": "passed"})
        e3 = create_event("deploy", {"deploy_status": "success"})
        
        result = self.evaluator.evaluate(contract, [e1, e2, e3])
        assert result.satisfied
        assert len(result.missing_evidence) == 0
        assert len(result.failed_evidence) == 0
        assert "Contract 'c_full' satisfied" in result.explanation

    def test_missing_evidence_multiple(self):
        contract = TaskContract(
            "c_full", "Full Deploy",
            required_evidence=("file_modified", "tests_executed", "tests_passed", "deployment_succeeded")
        )
        e1 = create_event("edit_file", {"path": "app.py"})
        
        result = self.evaluator.evaluate(contract, [e1])
        assert not result.satisfied
        assert len(result.missing_evidence) == 3
        assert "tests_executed" in result.missing_evidence
        assert "tests_passed" in result.missing_evidence
        assert "deployment_succeeded" in result.missing_evidence

    def test_deterministic_ordering(self):
        contract = TaskContract("c1", "Task", ("file_modified", "tests_executed"))
        e1 = create_event("edit_file", {"path": "app.py"})
        e2 = create_event("run_tests", {"test_status": "passed"})
        
        result = self.evaluator.evaluate(contract, [e1, e2])
        # observed_evidence should reflect the chronological order of events based on extraction
        assert result.observed_evidence == ("file_modified", "tests_executed", "tests_passed")

    def test_failed_deployment_blocks_satisfaction(self):
        contract = TaskContract("c1", "Task", ("deployment_succeeded",))
        e1 = create_event("deploy", {"deploy_status": "failed"})
        
        result = self.evaluator.evaluate(contract, [e1])
        assert not result.satisfied
        assert "deployment_succeeded" in result.failed_evidence

    def test_executed_deployment_does_not_satisfy(self):
        contract = TaskContract("c1", "Task", ("deployment_succeeded",))
        # Exists but no "deploy_status" metadata
        e1 = create_event("deploy", {"target": "prod"})
        
        result = self.evaluator.evaluate(contract, [e1])
        assert not result.satisfied
        assert "deployment_succeeded" in result.missing_evidence
        assert "deployment_succeeded" not in result.observed_evidence


class TestPublicAPI:
    def test_public_api_imports(self):
        from agentguard.outcome import (
            TaskContract,
            EvidenceItem,
            OutcomeAssessment,
            EvidenceStatus,
            EvidenceEvaluator,
        )
        assert EvidenceEvaluator is not None
        assert TaskContract is not None
