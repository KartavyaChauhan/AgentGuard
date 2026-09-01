"""Immutable data models for the deterministic outcome evidence layer."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class EvidenceStatus(Enum):
    """The status of a piece of observed evidence."""
    OBSERVED = "OBSERVED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class TaskContract:
    """An immutable definition of required and optional outcomes for a task."""
    contract_id: str
    task_name: str
    required_evidence: tuple[str, ...]
    optional_evidence: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Defensively copy metadata
        if self.metadata is not None:
            object.__setattr__(self, "metadata", copy.deepcopy(self.metadata))


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """An immutable record of observed outcome evidence."""
    evidence_id: str
    evidence_type: str
    event_id: str | None
    timestamp: datetime
    status: EvidenceStatus
    details: dict[str, Any]

    def __post_init__(self):
        # Defensively copy details to ensure no mutable state leaks
        if self.details is not None:
            object.__setattr__(self, "details", copy.deepcopy(self.details))


@dataclass(frozen=True, slots=True)
class OutcomeAssessment:
    """An immutable evaluation of a task's completion based on hard evidence."""
    contract_id: str
    satisfied: bool
    missing_evidence: tuple[str, ...]
    observed_evidence: tuple[str, ...]
    failed_evidence: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    explanation: str
