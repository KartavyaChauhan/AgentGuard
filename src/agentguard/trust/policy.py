"""Default configuration and policy thresholds for the Trust Engine."""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class TrustConfig:
    """Configurable thresholds and options for the Trust Engine."""
    risky_score_threshold: int = 50
    critical_score_threshold: int = 80


# Default configuration instance
DEFAULT_TRUST_CONFIG = TrustConfig()
