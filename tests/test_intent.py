import pytest
from agentguard.intent import (
    Capability,
    IntentConstraint,
    TaskIntent,
    capability_for_tool,
    capabilities_for_tools
)


def test_capability_values():
    assert Capability.FILE_READ.value == "FILE_READ"
    assert Capability.FILE_WRITE.value == "FILE_WRITE"
    assert Capability.SHELL.value == "SHELL"
    assert Capability.NETWORK.value == "NETWORK"
    assert Capability.ENCODING.value == "ENCODING"
    assert Capability.PRIVILEGED.value == "PRIVILEGED"
    assert Capability.TEST_EXECUTION.value == "TEST_EXECUTION"
    assert Capability.GIT.value == "GIT"
    assert Capability.COMPUTATION.value == "COMPUTATION"


def test_intent_constraint_immutability():
    constraint = IntentConstraint(capability=Capability.NETWORK, allowed=False, reason="No network")
    
    # Check it's frozen
    with pytest.raises(Exception):
        constraint.allowed = True


def test_intent_constraint_invalid_reason():
    with pytest.raises(ValueError, match="reason must be a string"):
        IntentConstraint(capability=Capability.NETWORK, allowed=False, reason=123)


def test_task_intent_creation():
    intent = TaskIntent(
        intent_id="task-123",
        description="A simple task",
        allowed_capabilities=(Capability.FILE_READ, Capability.FILE_WRITE),
        forbidden_capabilities=(Capability.NETWORK,),
        required_outcomes=("file_modified",),
        optional_outcomes=("tests_passed",),
        constraints=(IntentConstraint(Capability.NETWORK, False, "No outgoing connections"),)
    )
    assert intent.intent_id == "task-123"
    assert intent.description == "A simple task"
    assert Capability.FILE_READ in intent.allowed_capabilities
    assert Capability.NETWORK in intent.forbidden_capabilities


def test_task_intent_immutability():
    intent = TaskIntent(
        intent_id="task-123",
        description="A simple task",
        allowed_capabilities=(Capability.FILE_READ,),
        forbidden_capabilities=()
    )
    with pytest.raises(Exception):
        intent.intent_id = "task-456"


def test_task_intent_empty_id():
    with pytest.raises(ValueError, match="intent_id cannot be empty"):
        TaskIntent(
            intent_id="   ",
            description="A simple task",
            allowed_capabilities=(),
            forbidden_capabilities=()
        )


def test_task_intent_empty_description():
    with pytest.raises(ValueError, match="description cannot be empty"):
        TaskIntent(
            intent_id="task-123",
            description="",
            allowed_capabilities=(),
            forbidden_capabilities=()
        )


def test_task_intent_overlap_capabilities():
    with pytest.raises(ValueError, match="Capabilities cannot be both allowed and forbidden"):
        TaskIntent(
            intent_id="task-123",
            description="A simple task",
            allowed_capabilities=(Capability.FILE_READ, Capability.NETWORK),
            forbidden_capabilities=(Capability.NETWORK, Capability.SHELL)
        )


def test_task_intent_deterministic_serialization():
    intent = TaskIntent(
        intent_id="task-123",
        description="A simple task",
        allowed_capabilities=(Capability.NETWORK, Capability.FILE_READ),
        forbidden_capabilities=(Capability.SHELL, Capability.PRIVILEGED),
        required_outcomes=("B", "A"),
        optional_outcomes=("Z", "Y"),
        constraints=(
            IntentConstraint(Capability.SHELL, False, "No shell"),
            IntentConstraint(Capability.PRIVILEGED, False, "No root"),
        )
    )
    
    serialized = intent.to_dict()
    
    assert serialized["intent_id"] == "task-123"
    assert serialized["description"] == "A simple task"
    assert serialized["allowed_capabilities"] == ["FILE_READ", "NETWORK"]
    assert serialized["forbidden_capabilities"] == ["PRIVILEGED", "SHELL"]
    assert serialized["required_outcomes"] == ["A", "B"]
    assert serialized["optional_outcomes"] == ["Y", "Z"]
    
    constraints = serialized["constraints"]
    assert len(constraints) == 2
    assert constraints[0]["capability"] == "PRIVILEGED"
    assert constraints[1]["capability"] == "SHELL"


def test_capability_mapping():
    assert capability_for_tool("read_file") == Capability.FILE_READ
    assert capability_for_tool("edit_file") == Capability.FILE_WRITE
    assert capability_for_tool("shell") == Capability.SHELL
    assert capability_for_tool("http_request") == Capability.NETWORK
    assert capability_for_tool("base64_encode") == Capability.ENCODING
    assert capability_for_tool("sudo") == Capability.PRIVILEGED
    assert capability_for_tool("pytest") == Capability.TEST_EXECUTION
    assert capability_for_tool("git_commit") == Capability.GIT
    assert capability_for_tool("calculate") == Capability.COMPUTATION


def test_capability_case_insensitive():
    assert capability_for_tool("READ_FILE") == Capability.FILE_READ
    assert capability_for_tool("  Http_Request  ") == Capability.NETWORK


def test_capability_unknown_tool():
    assert capability_for_tool("unknown_tool") is None
    assert capability_for_tool("some_random_shell_command") is None


def test_capability_exact_matching():
    # It shouldn't match just because 'shell' is in the string
    assert capability_for_tool("not_a_shell") is None


def test_capabilities_for_tools():
    tools = ["read_file", "HTTP_REQUEST", "unknown"]
    result = capabilities_for_tools(tools)
    
    assert result == {
        "read_file": Capability.FILE_READ,
        "HTTP_REQUEST": Capability.NETWORK,
        "unknown": None
    }


def test_public_api():
    import agentguard.intent
    assert hasattr(agentguard.intent, "Capability")
    assert hasattr(agentguard.intent, "TaskIntent")
    assert hasattr(agentguard.intent, "IntentConstraint")
    assert hasattr(agentguard.intent, "capability_for_tool")
    assert hasattr(agentguard.intent, "capabilities_for_tools")
