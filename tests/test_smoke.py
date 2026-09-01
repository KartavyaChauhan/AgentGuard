"""Smoke tests — verify the package installs and basic wiring works."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Package import
# ---------------------------------------------------------------------------


class TestPackageImport:
    """Verify that the core modules are importable."""

    def test_import_agentguard(self) -> None:
        import agentguard

        assert hasattr(agentguard, "__version__")
        assert isinstance(agentguard.__version__, str)
        assert agentguard.__version__ != ""

    def test_import_config(self) -> None:
        from agentguard.config import AgentGuardConfig, config

        assert isinstance(config, AgentGuardConfig)

    def test_import_logging(self) -> None:
        from agentguard.logging import get_logger

        logger = get_logger("test")
        assert isinstance(logger, logging.Logger)

    def test_import_cli(self) -> None:
        from agentguard.cli import build_parser

        parser = build_parser()
        assert parser.prog == "agentguard"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfig:
    """Verify configuration defaults and environment-variable overrides."""

    def test_defaults(self) -> None:
        from agentguard.config import AgentGuardConfig

        cfg = AgentGuardConfig()
        assert cfg.log_level == "INFO"
        assert cfg.config_dir == Path(".agentguard")
        assert cfg.session_timeout_seconds == 3600

    def test_env_override(self) -> None:
        from agentguard.config import AgentGuardConfig

        with patch.dict(
            "os.environ",
            {"AGENTGUARD_LOG_LEVEL": "DEBUG", "AGENTGUARD_SESSION_TIMEOUT_SECONDS": "60"},
        ):
            cfg = AgentGuardConfig()
            assert cfg.log_level == "DEBUG"
            assert cfg.session_timeout_seconds == 60

    def test_immutable(self) -> None:
        from agentguard.config import AgentGuardConfig

        cfg = AgentGuardConfig()
        with pytest.raises(AttributeError):
            cfg.log_level = "DEBUG"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


class TestLogging:
    """Verify structured JSON logging output."""

    def test_json_output(self) -> None:
        import io

        from agentguard.logging import _JSONFormatter, get_logger

        logger = get_logger("test.json_output")

        # Attach a temporary handler with a StringIO stream so we can
        # inspect the formatted output without fighting pytest's log capture.
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(_JSONFormatter())
        logger.addHandler(handler)
        try:
            logger.warning("hello from test", extra={"foo": "bar"})
        finally:
            logger.removeHandler(handler)

        output = stream.getvalue().strip()
        record = json.loads(output)
        assert record["level"] == "WARNING"
        assert record["message"] == "hello from test"
        assert record["foo"] == "bar"
        assert "timestamp" in record


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCLI:
    """Verify CLI argument parsing."""

    def test_help(self) -> None:
        from agentguard.cli import build_parser

        parser = build_parser()
        help_text = parser.format_help()
        assert "agentguard" in help_text.lower()

    def test_version_flag(self) -> None:
        from agentguard.cli import build_parser

        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_main_returns_zero(self) -> None:
        from agentguard.cli import main

        assert main([]) == 0

    def test_cli_entrypoint(self) -> None:
        """Run ``agentguard --version`` as a subprocess to confirm the
        console-script entry point is wired correctly."""
        result = subprocess.run(
            [sys.executable, "-m", "agentguard.cli", "--version"],
            capture_output=True,
            text=True,
        )
        # --version causes SystemExit(0) which means the process exits 0.
        assert result.returncode == 0
        assert "agentguard" in result.stdout.lower()
