"""AgentGuard configuration.

Configuration is loaded once at startup.  Values come from (highest priority
first):

1. Explicit keyword arguments passed to ``AgentGuardConfig()``.
2. Environment variables prefixed with ``AGENTGUARD_``.
3. Built-in defaults.

A future iteration will layer on file-based policy configuration (YAML/TOML).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(key: str, default: str) -> str:
    """Read an ``AGENTGUARD_``-prefixed environment variable."""
    return os.environ.get(f"AGENTGUARD_{key}", default)


@dataclass(frozen=True, slots=True)
class AgentGuardConfig:
    """Immutable runtime configuration for AgentGuard.

    All fields have sensible defaults and can be overridden via environment
    variables (``AGENTGUARD_<FIELD>``).
    """

    # -- general ---------------------------------------------------------
    log_level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO"))

    # -- paths -----------------------------------------------------------
    config_dir: Path = field(
        default_factory=lambda: Path(_env("CONFIG_DIR", ".agentguard")),
    )

    # -- session ---------------------------------------------------------
    session_timeout_seconds: int = field(
        default_factory=lambda: int(_env("SESSION_TIMEOUT_SECONDS", "3600")),
    )


# Module-level singleton — importable as ``from agentguard.config import config``.
config = AgentGuardConfig()
