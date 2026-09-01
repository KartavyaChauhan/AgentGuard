from dataclasses import dataclass, field
from typing import List, Optional, Any
import sqlite3
import shutil
import tempfile
import os
import uuid
from datetime import datetime, timezone

from agentguard.audit.models import AuditEvent
from agentguard.audit.repository import AuditRepository
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.models import ExecutionStatus

@dataclass(frozen=True)
class AuditIsolationPolicy:
    """Explicitly defines the security boundaries the AgentGuard process expects."""
    agent_can_append: bool = True
    agent_can_modify: bool = False
    agent_can_delete: bool = False
    agent_can_verify: bool = True
    agent_can_read_raw_storage: bool = False

@dataclass(frozen=True)
class TamperScenario:
    scenario_id: str
    description: str
    attack_type: str
    target_session_id: str
    expected_detection: bool
    expected_integrity_state: str

@dataclass(frozen=True)
class TamperResult:
    scenario_id: str
    detected: bool
    integrity_valid: bool
    first_invalid_event_id: Optional[str]
    reason: Optional[str]
    events_before: int
    events_after: int

class AuditTamperRunner:
    def __init__(self):
        self.isolation_policy = AuditIsolationPolicy()
        
    def _create_clean_chain(self, repo: AuditRepository, session_id: str) -> List[AuditEvent]:
        events = []
        prev_hash = None
        for i in range(1, 5):
            ev = AuditEvent(
                event_id=f"ev_{i}",
                timestamp=datetime.now(timezone.utc),
                session_id=session_id,
                agent_id="test_agent",
                event_type="TOOL_EXECUTION",
                tool_name=f"tool_{i}",
                arguments_metadata={"arg1": "<str, len=5>"},
                policy_action=PolicyAction.ALLOW,
                risk_level=RiskLevel.LOW,
                execution_status=ExecutionStatus.EXECUTED,
                previous_event_hash=prev_hash
            )
            events.append(ev)
            repo.append(ev)
            prev_hash = ev.event_hash
        return events
        
    def run_scenario(self, scenario: TamperScenario) -> TamperResult:
        # Create a temp db
        fd, db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        
        try:
            repo = AuditRepository(db_path)
            repo.create_database()
            
            # Setup clean chain
            self._create_clean_chain(repo, scenario.target_session_id)
            
            events_before = repo.count_events()
            
            # Apply tampering via RAW SQL (simulating an external attacker or compromised process bypassing AgentGuard boundaries)
            self._apply_tamper(db_path, scenario)
            
            # Reconnect to get modified data length
            repo = AuditRepository(db_path)
            events_after = repo.count_events()
            
            # Verify the chain
            res = repo.verify_chain(scenario.target_session_id)
            
            # If tampering detected, log it (normally in a real system we would log this in the main DB)
            if not res.valid:
                tamper_event = AuditEvent(
                    event_id=uuid.uuid4().hex,
                    timestamp=datetime.now(timezone.utc),
                    session_id=scenario.target_session_id,
                    agent_id="system",
                    event_type="AUDIT_TAMPER_ATTEMPT",
                    tool_name="verify",
                    arguments_metadata={
                        "attack_type": scenario.attack_type,
                        "target_event_id": res.first_invalid_event_id,
                        "detection_status": "DETECTED"
                    },
                    policy_action=PolicyAction.DENY,
                    risk_level=RiskLevel.CRITICAL,
                    execution_status=ExecutionStatus.FAILED,
                    previous_event_hash=None # Not linking to compromised chain
                )
                try:
                    repo.append(tamper_event)
                except Exception:
                    pass # Ignore if db is completely broken
                    
            return TamperResult(
                scenario_id=scenario.scenario_id,
                detected=not res.valid,
                integrity_valid=res.valid,
                first_invalid_event_id=res.first_invalid_event_id,
                reason=res.reason,
                events_before=events_before,
                events_after=events_after
            )
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
                
    def _apply_tamper(self, db_path: str, scenario: TamperScenario):
        conn = sqlite3.connect(db_path)
        try:
            if scenario.attack_type == "MODIFY_EVENT":
                conn.execute("UPDATE audit_events SET tool_name = 'hacked' WHERE event_id = 'ev_2'")
            elif scenario.attack_type == "MODIFY_EVENT_HASH":
                conn.execute("UPDATE audit_events SET event_hash = 'fake_hash' WHERE event_id = 'ev_2'")
            elif scenario.attack_type == "MODIFY_PREVIOUS_HASH":
                conn.execute("UPDATE audit_events SET previous_event_hash = 'broken' WHERE event_id = 'ev_3'")
            elif scenario.attack_type == "DELETE_EVENT":
                conn.execute("DELETE FROM audit_events WHERE event_id = 'ev_1'")
            elif scenario.attack_type == "DELETE_MIDDLE_EVENT":
                conn.execute("DELETE FROM audit_events WHERE event_id = 'ev_2'")
            elif scenario.attack_type == "REORDER_EVENTS":
                # Swap timestamps between ev_2 and ev_3
                cursor = conn.cursor()
                t2 = cursor.execute("SELECT timestamp FROM audit_events WHERE event_id = 'ev_2'").fetchone()[0]
                t3 = cursor.execute("SELECT timestamp FROM audit_events WHERE event_id = 'ev_3'").fetchone()[0]
                conn.execute("UPDATE audit_events SET timestamp = ? WHERE event_id = 'ev_2'", (t3,))
                conn.execute("UPDATE audit_events SET timestamp = ? WHERE event_id = 'ev_3'", (t2,))
            elif scenario.attack_type == "INSERT_FAKE_EVENT":
                conn.execute("INSERT INTO audit_events (event_id, timestamp, session_id, agent_id, event_type, tool_name, arguments_metadata_json, policy_action, risk_level, execution_status, rule_id, duration_ms, previous_event_hash, event_hash) VALUES ('fake_ev', ?, ?, 'a', 'T', 't', '{}', 'ALLOW', 'LOW', 'EXECUTED', NULL, NULL, 'bad', 'bad')", (datetime.now(timezone.utc).isoformat(), scenario.target_session_id))
            elif scenario.attack_type == "BREAK_CHAIN":
                conn.execute("UPDATE audit_events SET previous_event_hash = 'nonexistent' WHERE event_id = 'ev_2'")
            elif scenario.attack_type == "DUPLICATE_EVENT":
                # Create duplicate event (same content, new ID) to simulate a replay attack
                conn.execute("""
                    INSERT INTO audit_events (
                        event_id, timestamp, session_id, agent_id, event_type, tool_name,
                        arguments_metadata_json, policy_action, risk_level, execution_status,
                        rule_id, duration_ms, previous_event_hash, event_hash
                    )
                    SELECT
                        'ev_2_dup', timestamp, session_id, agent_id, event_type, tool_name,
                        arguments_metadata_json, policy_action, risk_level, execution_status,
                        rule_id, duration_ms, previous_event_hash, event_hash
                    FROM audit_events WHERE event_id = 'ev_2'
                """)
            elif scenario.attack_type == "REPLACE_ARGUMENT_METADATA":
                conn.execute("UPDATE audit_events SET arguments_metadata_json = '{\"arg1\": \"<str, len=100>\"}' WHERE event_id = 'ev_2'")
                
            conn.commit()
        finally:
            conn.close()

def get_tamper_scenarios() -> List[TamperScenario]:
    return [
        TamperScenario("ts-1", "Modify tool name in an existing event", "MODIFY_EVENT", "s1", True, "FAILED"),
        TamperScenario("ts-2", "Directly modify an event's hash", "MODIFY_EVENT_HASH", "s1", True, "FAILED"),
        TamperScenario("ts-3", "Modify the previous_event_hash to break linkage", "MODIFY_PREVIOUS_HASH", "s1", True, "FAILED"),
        TamperScenario("ts-4", "Delete the first event in a chain", "DELETE_EVENT", "s1", True, "FAILED"),
        TamperScenario("ts-5", "Delete a middle event in a chain", "DELETE_MIDDLE_EVENT", "s1", True, "FAILED"),
        TamperScenario("ts-6", "Reorder two events chronologically", "REORDER_EVENTS", "s1", True, "FAILED"),
        TamperScenario("ts-7", "Insert a fake event into the chain", "INSERT_FAKE_EVENT", "s1", True, "FAILED"),
        TamperScenario("ts-8", "Point an event to a broken predecessor", "BREAK_CHAIN", "s1", True, "FAILED"),
        TamperScenario("ts-9", "Duplicate an existing event ID", "DUPLICATE_EVENT", "s1", True, "FAILED"),
        TamperScenario("ts-10", "Replace sanitized metadata", "REPLACE_ARGUMENT_METADATA", "s1", True, "FAILED"),
    ]
