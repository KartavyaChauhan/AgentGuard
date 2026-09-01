import copy
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from agentguard.events.models import ToolEvent
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.models import ExecutionStatus

def serialize_canonical(data: Any) -> str:
    """Deterministically serialize a dictionary to a JSON string."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'))

def sanitize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Sanitize arguments by preserving only metadata (keys, types, lengths)."""
    sanitized = {}
    if not arguments:
        return sanitized
        
    for key, value in arguments.items():
        if isinstance(value, str):
            sanitized[key] = f"<str, len={len(value)}>"
        elif isinstance(value, (int, float, bool)):
            sanitized[key] = f"<{type(value).__name__}>"
        elif isinstance(value, list):
            sanitized[key] = f"<list, len={len(value)}>"
        elif isinstance(value, dict):
            sanitized[key] = f"<dict, len={len(value)}>"
        elif value is None:
            sanitized[key] = "<NoneType>"
        else:
            sanitized[key] = f"<{type(value).__name__}>"
    return sanitized

@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: datetime
    session_id: str
    agent_id: Optional[str]
    event_type: str
    tool_name: str
    arguments_metadata: dict[str, Any]
    policy_action: PolicyAction
    risk_level: RiskLevel
    execution_status: ExecutionStatus
    rule_id: Optional[str] = None
    duration_ms: Optional[float] = None
    previous_event_hash: Optional[str] = None
    event_hash: str = field(init=False)
    
    def __post_init__(self):
        if self.timestamp.tzinfo is None:
            raise ValueError("AuditEvent timestamp must be timezone-aware.")
        if self.timestamp.tzinfo != timezone.utc:
            raise ValueError("AuditEvent timestamp must be in UTC.")
            
        object.__setattr__(self, "arguments_metadata", copy.deepcopy(self.arguments_metadata))
        
        # Calculate hash
        canonical = self.to_canonical_dict()
        serialized = serialize_canonical(canonical)
        
        hash_val = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
        object.__setattr__(self, "event_hash", hash_val)
        
    def to_canonical_dict(self) -> dict[str, Any]:
        """Convert the event (excluding event_hash) to a dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "event_type": self.event_type,
            "tool_name": self.tool_name,
            "arguments_metadata": self.arguments_metadata,
            "policy_action": self.policy_action.name if hasattr(self.policy_action, 'name') else str(self.policy_action),
            "risk_level": self.risk_level.name if hasattr(self.risk_level, 'name') else str(self.risk_level),
            "execution_status": self.execution_status.name if hasattr(self.execution_status, 'name') else str(self.execution_status),
            "rule_id": self.rule_id,
            "duration_ms": self.duration_ms,
            "previous_event_hash": self.previous_event_hash
        }

def create_audit_event_from_tool_event(tool_event: ToolEvent, previous_event_hash: Optional[str] = None) -> AuditEvent:
    """Safe conversion from ToolEvent to AuditEvent without mutating ToolEvent."""
    # Ensure UTC timestamp
    timestamp = tool_event.timestamp
    if timestamp.tzinfo is not timezone.utc:
        timestamp = timestamp.astimezone(timezone.utc)
        
    args_metadata = sanitize_arguments(tool_event.arguments)
    
    return AuditEvent(
        event_id=tool_event.event_id,
        timestamp=timestamp,
        session_id=tool_event.session_id,
        agent_id=tool_event.agent_id,
        event_type="TOOL_EXECUTION",
        tool_name=tool_event.tool_name,
        arguments_metadata=args_metadata,
        policy_action=tool_event.policy_action,
        risk_level=tool_event.risk_level,
        execution_status=tool_event.execution_status,
        rule_id=tool_event.rule_id,
        duration_ms=tool_event.duration_ms,
        previous_event_hash=previous_event_hash
    )
