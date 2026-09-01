from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid
from typing import Any

class IntegrityFindingType(str, Enum):
    TOOL_SCHEMA_CHANGED = "TOOL_SCHEMA_CHANGED"
    TOOL_DESCRIPTION_CHANGED = "TOOL_DESCRIPTION_CHANGED"
    TOOL_OUTPUT_SCHEMA_CHANGED = "TOOL_OUTPUT_SCHEMA_CHANGED"
    TOOL_RUG_PULL = "TOOL_RUG_PULL"
    TOOL_SHADOWING = "TOOL_SHADOWING"
    UNAPPROVED_NEW_TOOL = "UNAPPROVED_NEW_TOOL"


@dataclass(frozen=True)
class IntegrityFinding:
    finding_id: str
    timestamp: datetime
    fingerprint: str
    data_source: str
    type: IntegrityFindingType
    tool_name: str
    server_id: str
    details: dict[str, Any] = field(default_factory=dict)

def create_integrity_finding(
    finding_type: IntegrityFindingType,
    tool_name: str,
    server_id: str,
    fingerprint: str,
    details: dict[str, Any]
) -> IntegrityFinding:
    return IntegrityFinding(
        finding_id=uuid.uuid4().hex,
        timestamp=datetime.now(timezone.utc),
        fingerprint=fingerprint,
        data_source=f"tool_registry:{server_id}",
        type=finding_type,
        tool_name=tool_name,
        server_id=server_id,
        details=details
    )
