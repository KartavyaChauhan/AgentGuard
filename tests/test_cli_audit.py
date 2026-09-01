import os
import json
import pytest
from unittest.mock import patch
from io import StringIO
from datetime import datetime, timezone, timedelta

from agentguard.audit.models import AuditEvent
from agentguard.audit.repository import AuditRepository
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.models import ExecutionStatus
from agentguard.cli import main

def create_mock_event(event_id, session_id="s1", timestamp=None, previous_hash=None, tool_name="test_tool", action=PolicyAction.ALLOW, risk=RiskLevel.LOW):
    dt = timestamp or datetime.now(timezone.utc)
    return AuditEvent(
        event_id=event_id,
        timestamp=dt,
        session_id=session_id,
        agent_id="a1",
        event_type="TEST",
        tool_name=tool_name,
        arguments_metadata={"key": "<str, len=15>"}, # No secrets
        policy_action=action,
        risk_level=risk,
        execution_status=ExecutionStatus.EXECUTED,
        previous_event_hash=previous_hash
    )

@pytest.fixture
def temp_db(tmp_path):
    return str(tmp_path / "audit.sqlite3")

@pytest.fixture
def repo(temp_db):
    r = AuditRepository(temp_db)
    r.create_database()
    return r
    
def run_cli(*args, db_path=None):
    env = {}
    if db_path:
        env["AGENTGUARD_AUDIT_DB"] = db_path
        
    with patch("sys.stdout", new=StringIO()) as out, \
         patch("sys.stderr", new=StringIO()) as err, \
         patch.dict(os.environ, env):
        try:
            exit_code = main(list(args))
        except SystemExit as e:
            exit_code = e.code
            
        return exit_code, out.getvalue(), err.getvalue()

def test_audit_summary_empty(temp_db, repo):
    code, out, err = run_cli("audit", db_path=temp_db)
    assert code == 0
    assert "Events: 0" in out
    assert "Sessions: 0" in out
    assert "Integrity: VERIFIED" in out

def test_audit_summary_populated(temp_db, repo):
    e1 = create_mock_event("e1")
    repo.append(e1)
    
    code, out, err = run_cli("audit", db_path=temp_db)
    assert code == 0
    assert "Events: 1" in out
    assert "Sessions: 1" in out
    assert "Integrity: VERIFIED" in out

def test_audit_summary_json(temp_db, repo):
    repo.append(create_mock_event("e1"))
    
    code, out, err = run_cli("audit", "--json", db_path=temp_db)
    assert code == 0
    data = json.loads(out)
    assert data["event_count"] == 1
    assert data["session_count"] == 1
    assert data["integrity"] == "VERIFIED"

def test_audit_sessions_list(temp_db, repo):
    repo.append(create_mock_event("e1", session_id="sess_1"))
    
    code, out, err = run_cli("audit", "sessions", db_path=temp_db)
    assert code == 0
    assert "sess_1" in out
    
    code, out, err = run_cli("audit", "sessions", "--json", db_path=temp_db)
    assert code == 0
    data = json.loads(out)
    assert len(data) == 1
    assert data[0]["session_id"] == "sess_1"
    assert data[0]["events"] == 1

def test_audit_session_inspection(temp_db, repo):
    repo.append(create_mock_event("e1", session_id="sess_1", tool_name="secret_tool"))
    
    code, out, err = run_cli("audit", "session", "sess_1", db_path=temp_db)
    assert code == 0
    assert "sess_1" in out
    assert "secret_tool" in out
    assert "<str, len=15>" in out # sanitized args
    assert "my_secret_password" not in out # raw secret not present

def test_audit_session_nonexistent(temp_db, repo):
    code, out, err = run_cli("audit", "session", "missing", db_path=temp_db)
    assert code == 2
    assert "not found" in err.lower()

def test_audit_verify_success(temp_db, repo):
    e1 = create_mock_event("e1")
    repo.append(e1)
    
    code, out, err = run_cli("audit", "verify", db_path=temp_db)
    assert code == 0
    assert "VERIFIED" in out
    
    code, out, err = run_cli("audit", "verify", "--json", db_path=temp_db)
    assert code == 0
    data = json.loads(out)
    assert data["valid"] is True

def test_audit_verify_tampered_event(temp_db, repo):
    e1 = create_mock_event("e1")
    repo.append(e1)
    
    with repo._get_conn() as conn:
        conn.execute("UPDATE audit_events SET tool_name = 'hacked' WHERE event_id = 'e1'")
        conn.commit()
        
    code, out, err = run_cli("audit", "verify", db_path=temp_db)
    assert code == 1
    assert "FAILED" in out
    assert "recalculated hash does not match" in out.lower()

def test_audit_verify_deleted_event(temp_db, repo):
    e1 = create_mock_event("e1", timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc))
    e2 = create_mock_event("e2", timestamp=datetime(2025, 1, 2, tzinfo=timezone.utc), previous_hash=e1.event_hash)
    e3 = create_mock_event("e3", timestamp=datetime(2025, 1, 3, tzinfo=timezone.utc), previous_hash=e2.event_hash)
    repo.append(e1)
    repo.append(e2)
    repo.append(e3)
    
    with repo._get_conn() as conn:
        conn.execute("DELETE FROM audit_events WHERE event_id = 'e2'")
        conn.commit()
        
    code, out, err = run_cli("audit", "verify", db_path=temp_db)
    assert code == 1
    assert "FAILED" in out
    assert "previous_event_hash does not match" in out.lower()

def test_audit_verify_reordered_events(temp_db, repo):
    # If events are reordered by timestamp, the verification will process them in the wrong order
    # causing previous hash mismatch.
    e1 = create_mock_event("e1", timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc))
    e2 = create_mock_event("e2", timestamp=datetime(2025, 1, 2, tzinfo=timezone.utc), previous_hash=e1.event_hash)
    repo.append(e1)
    repo.append(e2)
    
    with repo._get_conn() as conn:
        # e2 happens before e1 now
        conn.execute("UPDATE audit_events SET timestamp = ? WHERE event_id = 'e2'", (datetime(2024, 1, 1, tzinfo=timezone.utc).isoformat(),))
        conn.commit()
        
    code, out, err = run_cli("audit", "verify", db_path=temp_db)
    assert code == 1
    assert "FAILED" in out

def test_audit_verify_specific_session(temp_db, repo):
    e1 = create_mock_event("e1", session_id="s1")
    repo.append(e1)
    
    code, out, err = run_cli("audit", "verify", "--session", "s1", db_path=temp_db)
    assert code == 0
    assert "s1" in out

def test_audit_nonexistent_database(tmp_path):
    db_path = str(tmp_path / "missing.sqlite3")
    
    code, out, err = run_cli("audit", db_path=db_path)
    assert code == 2
    assert "not found" in err.lower()
    
    code, out, err = run_cli("audit", "--json", db_path=db_path)
    assert code == 2
    data = json.loads(out)
    assert "error" in data
