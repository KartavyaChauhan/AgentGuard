"""Data flow immutable models."""

from __future__ import annotations

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Tuple, List

from agentguard.policy.models import RiskLevel

class DataClassification(Enum):
    PUBLIC = auto()
    INTERNAL = auto()
    SENSITIVE = auto()
    SECRET = auto()

@dataclass(frozen=True, slots=True)
class DataOrigin:
    origin_id: str
    event_id: str
    source_type: str
    source_identifier: str
    classification: DataClassification

@dataclass(frozen=True, slots=True)
class DataFlow:
    flow_id: str
    source_origin: DataOrigin
    transformations: Tuple[str, ...]
    destination: str
    classification: DataClassification
    event_ids: Tuple[str, ...]

@dataclass(frozen=True, slots=True)
class DataFinding:
    finding_id: str
    type: str
    severity: RiskLevel
    title: str
    description: str
    event_ids: Tuple[str, ...]
    classification: DataClassification
    source: str
    destination: str
    fingerprint: str

@dataclass(frozen=True, slots=True)
class DataInspectionResult:
    allowed: bool
    findings: Tuple[DataFinding, ...]
    classifications: Tuple[DataClassification, ...]
    fingerprints: Tuple[str, ...]

@dataclass(frozen=True, slots=True)
class ResponseFinding:
    finding_id: str
    type: str
    severity: RiskLevel
    tool_name: str
    event_id: str
    fingerprint: str
    description: str

@dataclass(frozen=True, slots=True)
class ToolDefinitionFinding:
    tool_name: str
    severity: RiskLevel
    finding_type: str
    description: str
    fingerprint: str
