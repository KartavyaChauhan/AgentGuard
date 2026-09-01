import uuid
from datetime import datetime, timezone
import pytest

from agentguard.events.models import ToolEvent
from agentguard.events.store import EventStore
from agentguard.policy.models import PolicyAction, RiskLevel, ToolRequest, PolicyDecision
from agentguard.execution.models import ExecutionStatus, ExecutionResult
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.rules import ToolNameRule, ApprovalRule
from agentguard.execution.executor import ToolExecutor


def create_event(
    session_id="sess-1",
    arguments=None,
    timestamp=None,
):
    if arguments is None:
        arguments = {"key": "value"}
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    return ToolEvent(
        event_id=uuid.uuid4().hex,
        timestamp=timestamp,
        session_id=session_id,
        agent_id="agent-1",
        tool_name="test_tool",
        arguments=arguments,
        policy_action=PolicyAction.ALLOW,
        risk_level=RiskLevel.LOW,
        execution_status=ExecutionStatus.EXECUTED,
        rule_id="rule-1",
        duration_ms=10.5,
    )

class TestToolEventModel:
    def test_immutability(self):
        event = create_event()
        with pytest.raises(Exception):
            event.tool_name = "other_tool"

    def test_timezone_awareness_enforced(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            create_event(timestamp=datetime.now())

    def test_defensive_copying_arguments(self):
        args = {"mutable": ["a"]}
        event = create_event(arguments=args)
        
        # Mutating the original dict should not affect the event
        args["mutable"].append("b")
        args["new_key"] = "x"
        
        assert event.arguments == {"mutable": ["a"]}
        
    def test_unique_event_ids_usually_created(self):
        e1 = create_event()
        e2 = create_event()
        assert e1.event_id != e2.event_id

    def test_valid_utc_timestamp_accepted(self):
        dt = datetime.now(timezone.utc)
        event = create_event(timestamp=dt)
        assert event.timestamp == dt

class TestEventStore:
    def test_record_and_get(self):
        store = EventStore()
        event = create_event()
        store.record(event)
        
        fetched = store.get(event.event_id)
        assert fetched is event

    def test_get_nonexistent(self):
        store = EventStore()
        assert store.get("fake-id") is None

    def test_session_isolation(self):
        store = EventStore()
        store.record(create_event(session_id="A"))
        store.record(create_event(session_id="B"))
        store.record(create_event(session_id="A"))
        
        assert store.count("A") == 2
        assert store.count("B") == 1
        assert store.count("C") == 0

    def test_get_session_events_insertion_order(self):
        store = EventStore()
        e1 = create_event(session_id="A")
        e2 = create_event(session_id="A")
        store.record(e1)
        store.record(e2)
        
        events = store.get_session_events("A")
        assert len(events) == 2
        assert events[0] is e1
        assert events[1] is e2

    def test_get_session_events_defensive_copy(self):
        store = EventStore()
        store.record(create_event(session_id="A"))
        
        events = store.get_session_events("A")
        events.clear()
        
        assert store.count("A") == 1

    def test_recent_events_limit(self):
        store = EventStore()
        events = [create_event(session_id="A") for _ in range(5)]
        for e in events:
            store.record(e)
            
        recent = store.recent_events("A", limit=2)
        assert len(recent) == 2
        assert recent[0] is events[3]
        assert recent[1] is events[4]

    def test_recent_events_limit_zero(self):
        store = EventStore()
        store.record(create_event(session_id="A"))
        assert len(store.recent_events("A", limit=0)) == 0

    def test_recent_events_limit_larger_than_store(self):
        store = EventStore()
        e = create_event(session_id="A")
        store.record(e)
        assert len(store.recent_events("A", limit=100)) == 1

    def test_recent_events_negative_limit(self):
        store = EventStore()
        with pytest.raises(ValueError):
            store.recent_events("A", limit=-1)

    def test_recent_events_defensive_copy(self):
        store = EventStore()
        store.record(create_event(session_id="A"))
        recent = store.recent_events("A", limit=1)
        recent.clear()
        assert store.count("A") == 1

    def test_clear_session(self):
        store = EventStore()
        e1 = create_event(session_id="A")
        store.record(e1)
        store.record(create_event(session_id="B"))
        
        store.clear("A")
        
        assert store.count("A") == 0
        assert store.count("B") == 1
        assert store.get(e1.event_id) is None


@pytest.fixture
def policy_engine():
    return PolicyEngine(rules=[
        ToolNameRule(
            id="deny-rule",
            description="Deny dangerous tool",
            action=PolicyAction.DENY,
            risk_level=RiskLevel.HIGH,
            priority=100,
            tool_name="dangerous_tool",
        ),
        ApprovalRule(
            id="approval-rule",
            description="Require approval",
            action=PolicyAction.REQUIRE_APPROVAL,
            risk_level=RiskLevel.MEDIUM,
            priority=100,
            tool_name="approval_tool",
        ),
    ])

class TestExecutorIntegration:
    def test_executor_records_allow(self, policy_engine):
        store = EventStore()
        executor = ToolExecutor(policy_engine=policy_engine, event_store=store)
        executor.register_tool("safe_tool", lambda x: f"result: {x}")
        
        req = ToolRequest(tool_name="safe_tool", arguments={"x": 1}, session_id="sess-x")
        result = executor.execute(req)
        
        assert result.status == ExecutionStatus.EXECUTED
        assert store.count("sess-x") == 1
        
        event = store.get_session_events("sess-x")[0]
        assert event.execution_status == ExecutionStatus.EXECUTED
        assert event.policy_action == PolicyAction.ALLOW
        assert event.duration_ms is not None
        assert event.arguments == {"x": 1}

    def test_executor_records_deny(self, policy_engine):
        store = EventStore()
        executor = ToolExecutor(policy_engine=policy_engine, event_store=store)
        
        req = ToolRequest(tool_name="dangerous_tool", session_id="sess-y")
        result = executor.execute(req)
        
        assert result.status == ExecutionStatus.DENIED
        assert store.count("sess-y") == 1
        
        event = store.get_session_events("sess-y")[0]
        assert event.execution_status == ExecutionStatus.DENIED
        assert event.policy_action == PolicyAction.DENY
        assert event.rule_id == "deny-rule"
        assert event.duration_ms is None

    def test_executor_records_require_approval(self, policy_engine):
        store = EventStore()
        executor = ToolExecutor(policy_engine=policy_engine, event_store=store)
        
        req = ToolRequest(tool_name="approval_tool", session_id="sess-z")
        executor.execute(req)
        
        event = store.get_session_events("sess-z")[0]
        assert event.execution_status == ExecutionStatus.APPROVAL_REQUIRED
        assert event.policy_action == PolicyAction.REQUIRE_APPROVAL
        assert event.duration_ms is None

    def test_executor_records_failed(self, policy_engine):
        store = EventStore()
        executor = ToolExecutor(policy_engine=policy_engine, event_store=store)
        
        def crashing_tool():
            raise RuntimeError("crash")
            
        executor.register_tool("crash_tool", crashing_tool)
        
        req = ToolRequest(tool_name="crash_tool", session_id="sess-fail")
        executor.execute(req)
        
        event = store.get_session_events("sess-fail")[0]
        assert event.execution_status == ExecutionStatus.FAILED
        assert event.policy_action == PolicyAction.ALLOW
        assert event.duration_ms is not None

    def test_executor_records_unknown_tool_failed(self, policy_engine):
        store = EventStore()
        executor = ToolExecutor(policy_engine=policy_engine, event_store=store)
        
        req = ToolRequest(tool_name="missing_tool", session_id="sess-miss")
        executor.execute(req)
        
        event = store.get_session_events("sess-miss")[0]
        assert event.execution_status == ExecutionStatus.FAILED
        assert event.policy_action == PolicyAction.ALLOW
        assert event.duration_ms is None

    def test_executor_works_normally_without_event_store(self, policy_engine):
        executor = ToolExecutor(policy_engine=policy_engine)
        executor.register_tool("safe_tool", lambda: "ok")
        
        req = ToolRequest(tool_name="safe_tool")
        result = executor.execute(req)
        assert result.status == ExecutionStatus.EXECUTED

    def test_session_id_auto_generated_if_missing(self, policy_engine):
        store = EventStore()
        executor = ToolExecutor(policy_engine=policy_engine, event_store=store)
        executor.register_tool("safe_tool", lambda: "ok")
        
        req = ToolRequest(tool_name="safe_tool", agent_id="agent-abc")
        assert req.session_id is None
        
        executor.execute(req)
        
        # We don't know the generated ID, but we can search the store
        # Since this is the only event, we can find it
        assert len(store._events_by_id) == 1
        event = list(store._events_by_id.values())[0]
        
        assert event.session_id is not None
        assert isinstance(event.session_id, str)
        assert event.agent_id == "agent-abc"
        
        # The request itself must remain unmodified
        assert req.session_id is None

    def test_agent_id_propagation(self, policy_engine):
        store = EventStore()
        executor = ToolExecutor(policy_engine=policy_engine, event_store=store)
        executor.register_tool("safe_tool", lambda: "ok")
        
        req = ToolRequest(tool_name="safe_tool", session_id="123", agent_id="agent-999")
        executor.execute(req)
        
        event = store.get_session_events("123")[0]
        assert event.agent_id == "agent-999"
