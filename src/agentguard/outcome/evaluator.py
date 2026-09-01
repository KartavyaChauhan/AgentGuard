"""Evaluator for extracting and verifying outcome evidence deterministically."""

from __future__ import annotations

import uuid
from typing import Sequence
from datetime import datetime, timezone

from agentguard.events.models import ToolEvent
from agentguard.execution.models import ExecutionStatus
from agentguard.outcome.models import (
    TaskContract,
    EvidenceItem,
    OutcomeAssessment,
    EvidenceStatus,
)


class EvidenceEvaluator:
    """Evaluates task execution outcomes deterministically based on tool events."""

    def __init__(self) -> None:
        # Configurable tool indicators
        self.test_execution_tools = {"run_tests", "pytest", "test", "npm_test"}
        self.file_modification_tools = {"edit_file", "write_file", "modify_file"}
        self.deployment_tools = {"deploy", "run_deploy", "deployment"}

    def _extract_evidence(self, events: Sequence[ToolEvent]) -> list[EvidenceItem]:
        """Scans tool events to extract evidence items deterministically."""
        extracted: list[EvidenceItem] = []

        for event in events:
            # We mostly care about executed tools (or explicitly failed ones if they generate failed evidence)
            is_executed = event.execution_status == ExecutionStatus.EXECUTED

            # 1. tests_executed & tests_passed
            if any(indicator in event.tool_name.lower() for indicator in self.test_execution_tools):
                # We saw a test tool execute
                if is_executed:
                    extracted.append(
                        EvidenceItem(
                            evidence_id=uuid.uuid4().hex,
                            evidence_type="tests_executed",
                            event_id=event.event_id,
                            timestamp=event.timestamp,
                            status=EvidenceStatus.OBSERVED,
                            details={"tool_name": event.tool_name},
                        )
                    )

                # Did tests pass? Requires explicit signal, not just execution status.
                # Check arguments/metadata. (In a real system, execution results would be checked too).
                test_status = event.arguments.get("test_status", "").lower()
                if test_status == "passed":
                    extracted.append(
                        EvidenceItem(
                            evidence_id=uuid.uuid4().hex,
                            evidence_type="tests_passed",
                            event_id=event.event_id,
                            timestamp=event.timestamp,
                            status=EvidenceStatus.VERIFIED,
                            details={"tool_name": event.tool_name, "test_status": test_status},
                        )
                    )
                elif test_status == "failed" or event.execution_status == ExecutionStatus.FAILED:
                    extracted.append(
                        EvidenceItem(
                            evidence_id=uuid.uuid4().hex,
                            evidence_type="tests_passed",  # It's evidence ABOUT tests_passed (that they failed)
                            event_id=event.event_id,
                            timestamp=event.timestamp,
                            status=EvidenceStatus.FAILED,
                            details={"tool_name": event.tool_name, "test_status": test_status},
                        )
                    )

            # 2. file_modified
            if any(indicator in event.tool_name.lower() for indicator in self.file_modification_tools):
                if is_executed:
                    # Do not store file contents. Just the path if available.
                    path = event.arguments.get("path") or event.arguments.get("filename") or "unknown"
                    extracted.append(
                        EvidenceItem(
                            evidence_id=uuid.uuid4().hex,
                            evidence_type="file_modified",
                            event_id=event.event_id,
                            timestamp=event.timestamp,
                            status=EvidenceStatus.VERIFIED,
                            details={"tool_name": event.tool_name, "file_path": path},
                        )
                    )

            # 3. deployment_succeeded
            if any(indicator in event.tool_name.lower() for indicator in self.deployment_tools):
                deploy_status = event.arguments.get("deploy_status", "").lower()
                if deploy_status == "success":
                    extracted.append(
                        EvidenceItem(
                            evidence_id=uuid.uuid4().hex,
                            evidence_type="deployment_succeeded",
                            event_id=event.event_id,
                            timestamp=event.timestamp,
                            status=EvidenceStatus.VERIFIED,
                            details={"tool_name": event.tool_name},
                        )
                    )
                elif deploy_status == "failed" or event.execution_status == ExecutionStatus.FAILED:
                    extracted.append(
                        EvidenceItem(
                            evidence_id=uuid.uuid4().hex,
                            evidence_type="deployment_succeeded",
                            event_id=event.event_id,
                            timestamp=event.timestamp,
                            status=EvidenceStatus.FAILED,
                            details={"tool_name": event.tool_name},
                        )
                    )

        return extracted

    def evaluate(self, contract: TaskContract, events: Sequence[ToolEvent]) -> OutcomeAssessment:
        """Determines if a task's contract is satisfied by the provided events."""
        extracted_evidence = self._extract_evidence(events)

        observed_types = []
        failed_types = []
        evidence_ids = []
        
        # Categorize all extracted evidence
        for item in extracted_evidence:
            evidence_ids.append(item.evidence_id)
            if item.status in (EvidenceStatus.OBSERVED, EvidenceStatus.VERIFIED):
                if item.evidence_type not in observed_types:
                    observed_types.append(item.evidence_type)
            elif item.status == EvidenceStatus.FAILED:
                if item.evidence_type not in failed_types:
                    failed_types.append(item.evidence_type)

        missing = []
        for req in contract.required_evidence:
            if req not in observed_types:
                missing.append(req)

        satisfied = len(missing) == 0 and len(failed_types) == 0

        # Construct explanation
        if satisfied:
            explanation = f"Contract '{contract.contract_id}' satisfied. All required evidence observed."
        else:
            reasons = []
            if missing:
                reasons.append(f"Missing required evidence: {', '.join(missing)}")
            if failed_types:
                reasons.append(f"Failed evidence observed: {', '.join(failed_types)}")
            explanation = f"Contract '{contract.contract_id}' not satisfied. " + "; ".join(reasons) + "."

        return OutcomeAssessment(
            contract_id=contract.contract_id,
            satisfied=satisfied,
            missing_evidence=tuple(missing),
            observed_evidence=tuple(observed_types),
            failed_evidence=tuple(failed_types),
            evidence_ids=tuple(evidence_ids),
            explanation=explanation,
        )
