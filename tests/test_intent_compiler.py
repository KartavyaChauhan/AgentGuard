import pytest

from agentguard.outcome.models import TaskContract
from agentguard.intent.models import TaskIntent, IntentConstraint
from agentguard.intent.capabilities import Capability
from agentguard.intent.compiler import compile_task_contract


def test_basic_contract_compilation():
    contract = TaskContract(
        contract_id="test-1",
        task_name="A task",
        required_evidence=("file_modified",)
    )
    
    intent = compile_task_contract(contract)
    
    assert isinstance(intent, TaskIntent)
    assert intent.intent_id.startswith("intent-")
    assert "test-1" in intent.description
    assert "file_modified" in intent.required_outcomes


def test_required_and_optional_evidence_inference():
    contract = TaskContract(
        contract_id="test-2",
        task_name="Another task",
        required_evidence=("tests_executed",),
        optional_evidence=("deployment_succeeded",)
    )
    
    intent = compile_task_contract(contract)
    
    assert Capability.TEST_EXECUTION in intent.allowed_capabilities
    assert Capability.NETWORK in intent.allowed_capabilities
    assert Capability.FILE_WRITE not in intent.allowed_capabilities
    
    assert Capability.NETWORK not in intent.forbidden_capabilities


def test_duplicate_capability_elimination():
    contract = TaskContract(
        contract_id="test-3",
        task_name="Task",
        required_evidence=("tests_executed", "tests_passed")
    )
    
    intent = compile_task_contract(contract)
    
    # Should only appear once, tuple length should be 1 for TEST_EXECUTION
    # Since TEST_EXECUTION is the only allowed capability inferred
    assert len(intent.allowed_capabilities) == 1
    assert intent.allowed_capabilities[0] == Capability.TEST_EXECUTION


def test_forbidden_network_and_privileged_inference():
    contract = TaskContract(
        contract_id="test-4",
        task_name="Task",
        required_evidence=("file_modified",)
    )
    
    intent = compile_task_contract(contract)
    
    assert Capability.NETWORK in intent.forbidden_capabilities
    assert Capability.PRIVILEGED in intent.forbidden_capabilities
    
    # Check constraints
    assert len(intent.constraints) == 2
    caps_in_constraints = {c.capability for c in intent.constraints}
    assert Capability.NETWORK in caps_in_constraints
    assert Capability.PRIVILEGED in caps_in_constraints
    assert all(c.allowed is False for c in intent.constraints)


def test_explicit_inferred_conflict_resolution():
    # If NETWORK is inferred as allowed, it must not be forbidden
    contract = TaskContract(
        contract_id="test-5",
        task_name="Deploy",
        required_evidence=("deployment_succeeded",)
    )
    
    intent = compile_task_contract(contract)
    
    assert Capability.NETWORK in intent.allowed_capabilities
    assert Capability.NETWORK not in intent.forbidden_capabilities
    
    # Only PRIVILEGED should be forbidden
    assert Capability.PRIVILEGED in intent.forbidden_capabilities
    assert len(intent.constraints) == 1
    assert intent.constraints[0].capability == Capability.PRIVILEGED


def test_unknown_evidence():
    contract = TaskContract(
        contract_id="test-6",
        task_name="Unknown",
        required_evidence=("some_weird_evidence",)
    )
    
    intent = compile_task_contract(contract)
    
    assert len(intent.allowed_capabilities) == 0
    assert "some_weird_evidence" in intent.required_outcomes


def test_empty_contract():
    contract = TaskContract(
        contract_id="empty-1",
        task_name="Empty",
        required_evidence=()
    )
    
    intent = compile_task_contract(contract)
    
    assert intent.intent_id != ""
    assert "requiring no specific outcomes" in intent.description
    assert len(intent.allowed_capabilities) == 0
    assert Capability.NETWORK in intent.forbidden_capabilities
    assert Capability.PRIVILEGED in intent.forbidden_capabilities


def test_deterministic_intent_id():
    c1 = TaskContract(contract_id="same-id", task_name="Task 1", required_evidence=())
    c2 = TaskContract(contract_id="same-id", task_name="Task 2", required_evidence=())
    
    i1 = compile_task_contract(c1)
    i2 = compile_task_contract(c2)
    
    assert i1.intent_id == i2.intent_id


def test_different_contract_ids():
    c1 = TaskContract(contract_id="id-1", task_name="Task", required_evidence=())
    c2 = TaskContract(contract_id="id-2", task_name="Task", required_evidence=())
    
    i1 = compile_task_contract(c1)
    i2 = compile_task_contract(c2)
    
    assert i1.intent_id != i2.intent_id


def test_immutability_preservation():
    # We should test that mutating the original contract doesn't mutate intent
    ev_list = ["tests_executed"]
    contract = TaskContract(
        contract_id="id",
        task_name="task",
        required_evidence=tuple(ev_list)
    )
    
    intent = compile_task_contract(contract)
    
    # Mutating original list doesn't affect tuple in contract or intent
    # But let's verify intent is frozen
    with pytest.raises(Exception):
        intent.allowed_capabilities = ()


def test_deterministic_serialization():
    contract = TaskContract(
        contract_id="test-json",
        task_name="Task",
        required_evidence=("deployment_succeeded", "tests_executed")
    )
    
    intent = compile_task_contract(contract)
    serialized = intent.to_dict()
    
    assert serialized["intent_id"] == intent.intent_id
    # Both sets should be sorted
    assert serialized["allowed_capabilities"] == ["NETWORK", "TEST_EXECUTION"]
    assert serialized["forbidden_capabilities"] == ["PRIVILEGED"]


def test_public_api_import():
    from agentguard.intent.compiler import compile_task_contract
    assert compile_task_contract is not None
