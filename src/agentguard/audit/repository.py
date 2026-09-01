import json
import sqlite3
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import List, Optional

from agentguard.audit.models import AuditEvent, serialize_canonical
from agentguard.audit.database import get_managed_connection, transaction, AuditPersistenceError, AuditChainError
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.models import ExecutionStatus

@dataclass
class AuditVerificationResult:
    valid: bool
    checked_events: int
    first_invalid_event_id: Optional[str] = None
    reason: Optional[str] = None

class AuditRepository:
    """Manages persistence of AuditEvents in SQLite."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        
    def _get_conn(self):
        return get_managed_connection(self.db_path)
        
    def create_database(self):
        """Initialize the database schema."""
        try:
            with self._get_conn() as conn:
                with transaction(conn) as cursor:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS audit_events (
                            event_id TEXT PRIMARY KEY,
                            timestamp TEXT NOT NULL,
                            session_id TEXT NOT NULL,
                            agent_id TEXT,
                            event_type TEXT NOT NULL,
                            tool_name TEXT NOT NULL,
                            arguments_metadata_json TEXT NOT NULL,
                            policy_action TEXT NOT NULL,
                            execution_status TEXT NOT NULL,
                            risk_level TEXT NOT NULL,
                            rule_id TEXT,
                            duration_ms REAL,
                            previous_event_hash TEXT,
                            event_hash TEXT NOT NULL
                        )
                    """)
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_session_id ON audit_events(session_id)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_tool_name ON audit_events(tool_name)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_hash ON audit_events(event_hash)")
        except sqlite3.Error as e:
            raise AuditPersistenceError(f"Failed to create database schema: {e}") from e

    def append(self, event: AuditEvent):
        """Append a new AuditEvent, ensuring chain integrity."""
        # Recalculate hash independently to verify the object wasn't tampered with
        canonical = event.to_canonical_dict()
        serialized = serialize_canonical(canonical)
        recalculated_hash = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
        
        if recalculated_hash != event.event_hash:
            raise AuditChainError("Event hash does not match recalculated hash. Tampering detected.")
            
        try:
            with self._get_conn() as conn:
                with transaction(conn) as cursor:
                    # Determine previous event for the same session
                    cursor.execute(
                        "SELECT event_hash FROM audit_events WHERE session_id = ? ORDER BY timestamp DESC, rowid DESC LIMIT 1",
                        (event.session_id,)
                    )
                    row = cursor.fetchone()
                    
                    if row:
                        stored_previous_hash = row["event_hash"]
                        if event.previous_event_hash != stored_previous_hash:
                            raise AuditChainError(
                                f"Chain discontinuity: expected previous hash '{stored_previous_hash}', "
                                f"but event provided '{event.previous_event_hash}'."
                            )
                    else:
                        if event.previous_event_hash is not None:
                            raise AuditChainError(
                                f"Chain discontinuity: session has no events, but event provided previous hash '{event.previous_event_hash}'."
                            )
                            
                    cursor.execute("""
                        INSERT INTO audit_events (
                            event_id, timestamp, session_id, agent_id, event_type, tool_name,
                            arguments_metadata_json, policy_action, execution_status, risk_level,
                            rule_id, duration_ms, previous_event_hash, event_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_id,
                        event.timestamp.isoformat(),
                        event.session_id,
                        event.agent_id,
                        event.event_type,
                        event.tool_name,
                        json.dumps(event.arguments_metadata),
                        event.policy_action.name if hasattr(event.policy_action, 'name') else str(event.policy_action),
                        event.execution_status.name if hasattr(event.execution_status, 'name') else str(event.execution_status),
                        event.risk_level.name if hasattr(event.risk_level, 'name') else str(event.risk_level),
                        event.rule_id,
                        event.duration_ms,
                        event.previous_event_hash,
                        event.event_hash
                    ))
        except sqlite3.IntegrityError as e:
            raise AuditPersistenceError(f"Database integrity error (e.g., duplicate ID): {e}") from e
        except sqlite3.Error as e:
            raise AuditPersistenceError(f"Database error during append: {e}") from e

    def _row_to_event(self, row: sqlite3.Row) -> AuditEvent:
        # Bypass freezing dynamically or just construct a new instance
        # We must reconstruct the AuditEvent properly
        
        args_metadata = json.loads(row["arguments_metadata_json"])
        timestamp = datetime.fromisoformat(row["timestamp"])
        if timestamp.tzinfo is None:
            # Enforce UTC if missing, but it should have it
            timestamp = timestamp.replace(tzinfo=timezone.utc)
            
        policy_action = PolicyAction[row["policy_action"]] if hasattr(PolicyAction, row["policy_action"]) else row["policy_action"]
        risk_level = RiskLevel[row["risk_level"]] if hasattr(RiskLevel, row["risk_level"]) else row["risk_level"]
        execution_status = ExecutionStatus[row["execution_status"]] if hasattr(ExecutionStatus, row["execution_status"]) else row["execution_status"]
        
        event = AuditEvent(
            event_id=row["event_id"],
            timestamp=timestamp,
            session_id=row["session_id"],
            agent_id=row["agent_id"],
            event_type=row["event_type"],
            tool_name=row["tool_name"],
            arguments_metadata=args_metadata,
            policy_action=policy_action,
            risk_level=risk_level,
            execution_status=execution_status,
            rule_id=row["rule_id"],
            duration_ms=row["duration_ms"],
            previous_event_hash=row["previous_event_hash"]
        )
        
        # Override the calculated hash if it was somehow different, though it shouldn't be
        # We want to represent EXACTLY what is in the DB
        object.__setattr__(event, "event_hash", row["event_hash"])
        return event

    def get_event(self, event_id: str) -> Optional[AuditEvent]:
        try:
            with self._get_conn() as conn:
                cursor = conn.execute("SELECT * FROM audit_events WHERE event_id = ?", (event_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_event(row)
                return None
        except sqlite3.Error as e:
            raise AuditPersistenceError(f"Database error during get_event: {e}") from e

    def get_session_events(self, session_id: str) -> List[AuditEvent]:
        try:
            with self._get_conn() as conn:
                cursor = conn.execute("SELECT * FROM audit_events WHERE session_id = ? ORDER BY timestamp ASC, rowid ASC", (session_id,))
                return [self._row_to_event(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise AuditPersistenceError(f"Database error: {e}") from e

    def get_recent_events(self, limit: int) -> List[AuditEvent]:
        try:
            with self._get_conn() as conn:
                cursor = conn.execute("SELECT * FROM audit_events ORDER BY timestamp DESC, rowid DESC LIMIT ?", (limit,))
                return [self._row_to_event(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise AuditPersistenceError(f"Database error: {e}") from e
            
    def get_all_sessions(self) -> List[str]:
        try:
            with self._get_conn() as conn:
                cursor = conn.execute("SELECT DISTINCT session_id FROM audit_events ORDER BY session_id ASC")
                return [row["session_id"] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise AuditPersistenceError(f"Database error: {e}") from e
            
    def get_events_by_tool(self, tool_name: str) -> List[AuditEvent]:
        try:
            with self._get_conn() as conn:
                cursor = conn.execute("SELECT * FROM audit_events WHERE tool_name = ? ORDER BY timestamp DESC, rowid DESC", (tool_name,))
                return [self._row_to_event(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise AuditPersistenceError(f"Database error: {e}") from e
            
    def get_events_by_action(self, policy_action: PolicyAction) -> List[AuditEvent]:
        action_str = policy_action.name if hasattr(policy_action, 'name') else str(policy_action)
        try:
            with self._get_conn() as conn:
                cursor = conn.execute("SELECT * FROM audit_events WHERE policy_action = ? ORDER BY timestamp DESC, rowid DESC", (action_str,))
                return [self._row_to_event(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise AuditPersistenceError(f"Database error: {e}") from e

    def get_events_by_risk(self, risk_level: RiskLevel) -> List[AuditEvent]:
        risk_str = risk_level.name if hasattr(risk_level, 'name') else str(risk_level)
        try:
            with self._get_conn() as conn:
                cursor = conn.execute("SELECT * FROM audit_events WHERE risk_level = ? ORDER BY timestamp DESC, rowid DESC", (risk_str,))
                return [self._row_to_event(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise AuditPersistenceError(f"Database error: {e}") from e

    def count_events(self) -> int:
        try:
            with self._get_conn() as conn:
                cursor = conn.execute("SELECT COUNT(*) as c FROM audit_events")
                return cursor.fetchone()["c"]
        except sqlite3.Error as e:
            raise AuditPersistenceError(f"Database error: {e}") from e

    def verify_chain(self, session_id: str) -> AuditVerificationResult:
        """Verify the integrity of a session's event chain."""
        try:
            events = self.get_session_events(session_id)
            if not events:
                return AuditVerificationResult(valid=True, checked_events=0)
                
            expected_previous_hash = None
            checked = 0
            
            for event in events:
                if event.previous_event_hash != expected_previous_hash:
                    return AuditVerificationResult(
                        valid=False,
                        checked_events=checked,
                        first_invalid_event_id=event.event_id,
                        reason="Broken chain: previous_event_hash does not match the actual previous event hash."
                    )
                    
                # Recalculate the hash
                canonical = event.to_canonical_dict()
                serialized = serialize_canonical(canonical)
                recalculated_hash = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
                
                if recalculated_hash != event.event_hash:
                    return AuditVerificationResult(
                        valid=False,
                        checked_events=checked,
                        first_invalid_event_id=event.event_id,
                        reason="Tampered event: recalculated hash does not match stored event_hash."
                    )
                    
                expected_previous_hash = event.event_hash
                checked += 1
                
            return AuditVerificationResult(valid=True, checked_events=checked)
        except Exception as e:
            return AuditVerificationResult(
                valid=False,
                checked_events=0,
                reason=f"Verification failed due to error: {e}"
            )
