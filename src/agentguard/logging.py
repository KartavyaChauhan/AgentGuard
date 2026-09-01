"""Structured logging for AgentGuard.

Provides a thin wrapper around :mod:`logging` that emits structured
JSON-formatted log records.  This makes logs easy to parse by
log-aggregation tools while staying human-readable during development.

Usage::

    from agentguard.logging import get_logger

    logger = get_logger(__name__)
    logger.info("tool call inspected", extra={"tool": "bash", "action": "allow"})
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class _JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Merge any extra keys the caller passed via ``extra={…}``.
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord(
                "", 0, "", 0, None, None, None
            ).__dict__ and key not in ("message", "msg"):
                payload[key] = value

        return json.dumps(payload, default=str)


_configured: bool = False


def setup_logging(level: str = "INFO") -> None:
    """Configure the root ``agentguard`` logger.

    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _configured  # noqa: PLW0603
    if _configured:
        return

    root = logging.getLogger("agentguard")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JSONFormatter())
    root.addHandler(handler)

    # Prevent log messages from propagating to the root logger and being
    # printed twice when a third-party library configures logging globally.
    root.propagate = False

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``agentguard`` namespace.

    Automatically calls :func:`setup_logging` the first time a logger is
    requested.
    """
    setup_logging()
    return logging.getLogger(name if name.startswith("agentguard") else f"agentguard.{name}")
