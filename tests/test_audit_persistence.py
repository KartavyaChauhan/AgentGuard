import pytest
import sqlite3
import tempfile
import os
from datetime import datetime, timezone, timedelta

from agentguard.audit.models import AuditEvent
from agentguard.audit.repository import AuditRepository
from agentguard.audit.database import AuditPersistenceError, AuditChainError
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.models import ExecutionStatus

@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    yield path
    os.remove(path)

@pytest.fixture
def repo(temp_db):
    r = AuditRepository(temp_db)
    r.create_database()
    return r

def create_mock_event(event_id, session_id="s1", timestamp=None, previous_hash=None, tool_name="test_tool", action=PolicyAction.ALLOW, risk=RiskLevel.LOW):
    dt = timestamp or datetime.now(timezone.utc)
    return AuditEvent(
        event_id=event_id,
        timestamp=dt,
        session_id=session_id,
        agent_id="a1",
        event_type="TEST",
        tool_name=tool_name,
        arguments_metadata={"key": "<str, len=5>"},
        policy_action=action,
        risk_level=risk,
        execution_status=ExecutionStatus.EXECUTED,
        previous_event_hash=previous_hash
    )

def test_database_creation(repo):
    assert repo.count_events() == 0

def test_append_and_retrieve(repo):
    event = create_mock_event("e1")
    repo.append(event)
    
    assert repo.count_events() == 1
    retrieved = repo.get_event("e1")
    
    assert retrieved is not None
    assert retrieved.event_id == "e1"
    assert retrieved.session_id == "s1"
    assert retrieved.tool_name == "test_tool"
    assert retrieved.event_hash == event.event_hash

def test_hash_chain_enforcement(repo):
    e1 = create_mock_event("e1", timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc))
    repo.append(e1)
    
    # Valid next event
    e2 = create_mock_event("e2", timestamp=datetime(2025, 1, 2, tzinfo=timezone.utc), previous_hash=e1.event_hash)
    repo.append(e2)
    
    # Invalid next event (wrong previous hash)
    e3_invalid = create_mock_event("e3", timestamp=datetime(2025, 1, 3, tzinfo=timezone.utc), previous_hash="wrong")
    with pytest.raises(AuditChainError, match="Chain discontinuity"):
        repo.append(e3_invalid)

def test_invalid_first_event_hash(repo):
    # If it's the first event, previous_hash MUST be None
    e1 = create_mock_event("e1", previous_hash="not_none")
    with pytest.raises(AuditChainError):
        repo.append(e1)

def test_tampered_event_rejection(repo):
    e1 = create_mock_event("e1")
    # Tamper with the event hash in memory
    object.__setattr__(e1, "event_hash", "tampered_hash")
    
    with pytest.raises(AuditChainError, match="does not match recalculated hash"):
        repo.append(e1)

def test_verify_chain_valid(repo):
    e1 = create_mock_event("e1", timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc))
    e2 = create_mock_event("e2", timestamp=datetime(2025, 1, 2, tzinfo=timezone.utc), previous_hash=e1.event_hash)
    e3 = create_mock_event("e3", timestamp=datetime(2025, 1, 3, tzinfo=timezone.utc), previous_hash=e2.event_hash)
    
    repo.append(e1)
    repo.append(e2)
    repo.append(e3)
    
    result = repo.verify_chain("s1")
    assert result.valid is True
    assert result.checked_events == 3

def test_verify_chain_detects_tampering(repo):
    e1 = create_mock_event("e1")
    repo.append(e1)
    
    # Manually tamper with the database
    with repo._get_conn() as conn:
        conn.execute("UPDATE audit_events SET tool_name = 'hacked' WHERE event_id = 'e1'")
        conn.commit()
        
    result = repo.verify_chain("s1")
    assert result.valid is False
    assert result.checked_events == 0
    assert result.first_invalid_event_id == "e1"
    assert "recalculated hash does not match" in result.reason

def test_verify_chain_detects_deletion(repo):
    e1 = create_mock_event("e1", timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc))
    e2 = create_mock_event("e2", timestamp=datetime(2025, 1, 2, tzinfo=timezone.utc), previous_hash=e1.event_hash)
    e3 = create_mock_event("e3", timestamp=datetime(2025, 1, 3, tzinfo=timezone.utc), previous_hash=e2.event_hash)
    
    repo.append(e1)
    repo.append(e2)
    repo.append(e3)
    
    # Manually delete middle event
    with repo._get_conn() as conn:
        conn.execute("DELETE FROM audit_events WHERE event_id = 'e2'")
        conn.commit()
        
    result = repo.verify_chain("s1")
    assert result.valid is False
    # Checked e1 successfully, e3 fails because e3's prev hash is e2, but it expected e1
    assert result.checked_events == 1
    assert result.first_invalid_event_id == "e3"
    assert "previous_event_hash does not match" in result.reason

def test_query_methods(repo):
    dt_base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    e1 = create_mock_event("e1", timestamp=dt_base, tool_name="read_file", action=PolicyAction.ALLOW)
    e2 = create_mock_event("e2", timestamp=dt_base + timedelta(seconds=1), previous_hash=e1.event_hash, tool_name="read_file", action=PolicyAction.DENY)
    e3 = create_mock_event("e3", timestamp=dt_base + timedelta(seconds=2), previous_hash=e2.event_hash, tool_name="http_request", action=PolicyAction.ALLOW)
    
    repo.append(e1)
    repo.append(e2)
    repo.append(e3)
    
    assert len(repo.get_session_events("s1")) == 3
    
    recent = repo.get_recent_events(2)
    assert len(recent) == 2
    assert recent[0].event_id == "e3" # Descending timestamp
    assert recent[1].event_id == "e2"
    
    assert len(repo.get_events_by_tool("read_file")) == 2
    assert len(repo.get_events_by_tool("http_request")) == 1
    
    assert len(repo.get_events_by_action(PolicyAction.ALLOW)) == 2
    assert len(repo.get_events_by_action(PolicyAction.DENY)) == 1

def test_duplicate_event_rejection(repo):
    e1 = create_mock_event("e1", session_id="s1")
    repo.append(e1)
    
    # Try appending an event with the same ID but a different session to bypass chain discontinuity check
    e1_duplicate = create_mock_event("e1", session_id="s2")
    
    with pytest.raises(AuditPersistenceError, match="UNIQUE constraint failed"):
        repo.append(e1_duplicate)

def test_sqlite_failure_handling(temp_db):
    repo = AuditRepository(temp_db)
    repo.create_database()
    
    # Simulate a locked/closed database
    # Passing an invalid path to a new repo instance
    bad_repo = AuditRepository("/invalid/path/db.sqlite")
    
    e1 = create_mock_event("e1")
    with pytest.raises(AuditPersistenceError):
        bad_repo.append(e1)

def test_multiple_sessions(repo):
    e1 = create_mock_event("e1", session_id="s1")
    repo.append(e1)
    
    e2 = create_mock_event("e2", session_id="s2")
    repo.append(e2)
    
    assert len(repo.get_session_events("s1")) == 1
    assert len(repo.get_session_events("s2")) == 1

def test_sanitized_metadata_persistence(repo):
    e1 = create_mock_event("e1")
    repo.append(e1)
    
    with repo._get_conn() as conn:
        cursor = conn.execute("SELECT arguments_metadata_json FROM audit_events WHERE event_id = 'e1'")
        row = cursor.fetchone()
        assert "len=5" in row[0]
        assert "secret" not in row[0].lower() # assuming no secret word in mock

def test_persistence_across_instances(temp_db):
    repo1 = AuditRepository(temp_db)
    repo1.create_database()
    e1 = create_mock_event("e1")
    repo1.append(e1)
    
    repo2 = AuditRepository(temp_db)
    # Don't create database again, just read
    e1_retrieved = repo2.get_event("e1")
    assert e1_retrieved is not None
    assert e1_retrieved.event_id == "e1"
