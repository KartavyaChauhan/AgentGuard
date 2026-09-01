import pytest
from datetime import datetime, timezone, timedelta
import copy
import json

from agentguard.audit.models import (
    AuditEvent,
    sanitize_arguments,
    serialize_canonical,
    create_audit_event_from_tool_event
)
from agentguard.events.models import ToolEvent
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.models import ExecutionStatus

def test_sanitize_arguments():
    raw_args = {
        "secret": "my-super-secret-key",
        "count": 42,
        "is_active": True,
        "items": [1, 2, 3],
        "nested": {"a": "b"},
        "empty": None
    }
    
    sanitized = sanitize_arguments(raw_args)
    
    assert "my-super-secret-key" not in str(sanitized)
    assert sanitized["secret"] == "<str, len=19>"
    assert sanitized["count"] == "<int>"
    assert sanitized["is_active"] == "<bool>"
    assert sanitized["items"] == "<list, len=3>"
    assert sanitized["nested"] == "<dict, len=1>"
    assert sanitized["empty"] == "<NoneType>"

def test_audit_event_immutability():
    dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
    event = AuditEvent(
        event_id="1",
        timestamp=dt,
        session_id="s1",
        agent_id="a1",
        event_type="TEST",
        tool_name="tool1",
        arguments_metadata={"k": "v"},
        policy_action=PolicyAction.ALLOW,
        risk_level=RiskLevel.LOW,
        execution_status=ExecutionStatus.EXECUTED
    )
    
    with pytest.raises(Exception):
        event.event_id = "2"
        
def test_timezone_validation():
    # Naive timestamp
    with pytest.raises(ValueError, match="must be timezone-aware"):
        AuditEvent(
            event_id="1",
            timestamp=datetime(2025, 1, 1),
            session_id="s1",
            agent_id="a1",
            event_type="TEST",
            tool_name="tool1",
            arguments_metadata={},
            policy_action=PolicyAction.ALLOW,
            risk_level=RiskLevel.LOW,
            execution_status=ExecutionStatus.EXECUTED
        )
        
    # Non-UTC timezone
    est = timezone(timedelta(hours=-5))
    with pytest.raises(ValueError, match="must be in UTC"):
        AuditEvent(
            event_id="1",
            timestamp=datetime(2025, 1, 1, tzinfo=est),
            session_id="s1",
            agent_id="a1",
            event_type="TEST",
            tool_name="tool1",
            arguments_metadata={},
            policy_action=PolicyAction.ALLOW,
            risk_level=RiskLevel.LOW,
            execution_status=ExecutionStatus.EXECUTED
        )

def test_defensive_copying():
    meta = {"list": ["a", "b"]}
    dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
    event = AuditEvent(
        event_id="1",
        timestamp=dt,
        session_id="s1",
        agent_id="a1",
        event_type="TEST",
        tool_name="tool1",
        arguments_metadata=meta,
        policy_action=PolicyAction.ALLOW,
        risk_level=RiskLevel.LOW,
        execution_status=ExecutionStatus.EXECUTED
    )
    
    # Mutating original should not affect event
    meta["list"].append("c")
    assert "c" not in event.arguments_metadata["list"]

def test_deterministic_serialization_and_hashing():
    dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
    event1 = AuditEvent(
        event_id="1",
        timestamp=dt,
        session_id="s1",
        agent_id="a1",
        event_type="TEST",
        tool_name="tool1",
        arguments_metadata={"a": 1, "b": 2}, # order reversed from event2
        policy_action=PolicyAction.ALLOW,
        risk_level=RiskLevel.LOW,
        execution_status=ExecutionStatus.EXECUTED,
        previous_event_hash="prev1"
    )
    
    event2 = AuditEvent(
        event_id="1",
        timestamp=dt,
        session_id="s1",
        agent_id="a1",
        event_type="TEST",
        tool_name="tool1",
        arguments_metadata={"b": 2, "a": 1},
        policy_action=PolicyAction.ALLOW,
        risk_level=RiskLevel.LOW,
        execution_status=ExecutionStatus.EXECUTED,
        previous_event_hash="prev1"
    )
    
    assert event1.event_hash == event2.event_hash
    assert len(event1.event_hash) == 64 # SHA-256

def test_different_data_produces_different_hashes():
    dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
    base_kwargs = {
        "event_id": "1",
        "timestamp": dt,
        "session_id": "s1",
        "agent_id": "a1",
        "event_type": "TEST",
        "tool_name": "tool1",
        "arguments_metadata": {},
        "policy_action": PolicyAction.ALLOW,
        "risk_level": RiskLevel.LOW,
        "execution_status": ExecutionStatus.EXECUTED
    }
    
    event1 = AuditEvent(**base_kwargs)
    event2 = AuditEvent(**{**base_kwargs, "tool_name": "tool2"})
    
    assert event1.event_hash != event2.event_hash

def test_previous_event_hash_changes_event_hash():
    dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
    base_kwargs = {
        "event_id": "1",
        "timestamp": dt,
        "session_id": "s1",
        "agent_id": "a1",
        "event_type": "TEST",
        "tool_name": "tool1",
        "arguments_metadata": {},
        "policy_action": PolicyAction.ALLOW,
        "risk_level": RiskLevel.LOW,
        "execution_status": ExecutionStatus.EXECUTED
    }
    
    event1 = AuditEvent(**base_kwargs)
    event2 = AuditEvent(**{**base_kwargs, "previous_event_hash": "somehash"})
    
    assert event1.event_hash != event2.event_hash

def test_tampering_detection():
    dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
    event = AuditEvent(
        event_id="1",
        timestamp=dt,
        session_id="s1",
        agent_id="a1",
        event_type="TEST",
        tool_name="tool1",
        arguments_metadata={},
        policy_action=PolicyAction.ALLOW,
        risk_level=RiskLevel.LOW,
        execution_status=ExecutionStatus.EXECUTED
    )
    
    # Simulate tampering by bypassing frozen attribute
    object.__setattr__(event, "tool_name", "tampered")
    
    # Recalculating hash manually should show it doesn't match stored hash
    canonical = event.to_canonical_dict()
    import hashlib
    new_hash = hashlib.sha256(serialize_canonical(canonical).encode()).hexdigest()
    
    assert new_hash != event.event_hash

def test_conversion_from_tool_event():
    est = timezone(timedelta(hours=-5))
    dt = datetime(2025, 1, 1, tzinfo=est)
    
    tool_event = ToolEvent(
        event_id="t1",
        timestamp=dt,
        session_id="s1",
        agent_id="a1",
        tool_name="read_file",
        arguments={"path": ".env"},
        policy_action=PolicyAction.DENY,
        risk_level=RiskLevel.CRITICAL,
        execution_status=ExecutionStatus.DENIED,
        rule_id="rule1",
        duration_ms=10.5
    )
    
    audit_event = create_audit_event_from_tool_event(tool_event, previous_event_hash="prev")
    
    # Verify mapping
    assert audit_event.event_id == "t1"
    assert audit_event.session_id == "s1"
    assert audit_event.agent_id == "a1"
    assert audit_event.event_type == "TOOL_EXECUTION"
    assert audit_event.tool_name == "read_file"
    assert audit_event.policy_action == PolicyAction.DENY
    assert audit_event.risk_level == RiskLevel.CRITICAL
    assert audit_event.execution_status == ExecutionStatus.DENIED
    assert audit_event.rule_id == "rule1"
    assert audit_event.duration_ms == 10.5
    assert audit_event.previous_event_hash == "prev"
    
    # Verify timezone conversion to UTC
    assert audit_event.timestamp.tzinfo == timezone.utc
    assert audit_event.timestamp == dt.astimezone(timezone.utc)
    
    # Verify sanitization
    assert "path" in audit_event.arguments_metadata
    assert ".env" not in audit_event.arguments_metadata.values()
    assert ".env" not in str(audit_event.arguments_metadata)
