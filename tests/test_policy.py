"""Comprehensive tests for the deterministic policy engine."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from unittest.mock import patch

import pytest

from agentguard.policy import (
    PolicyAction,
    PolicyDecision,
    PolicyEngine,
    RiskLevel,
    ToolRequest,
)
from agentguard.policy.defaults import DEFAULT_RULES
from agentguard.policy.rules import (
    ApprovalRule,
    ArgumentPatternRule,
    PolicyRule,
    ToolNameRule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _engine() -> PolicyEngine:
    """Return an engine loaded with the default demo rules."""
    return PolicyEngine(rules=list(DEFAULT_RULES))


# ---------------------------------------------------------------------------
# ToolRequest
# ---------------------------------------------------------------------------


class TestToolRequest:
    """ToolRequest model tests."""

    def test_defaults(self) -> None:
        req = ToolRequest(tool_name="test")
        assert req.tool_name == "test"
        assert req.arguments == {}
        assert req.agent_id is None
        assert req.session_id is None

    def test_immutability(self) -> None:
        req = ToolRequest(tool_name="test")
        with pytest.raises(FrozenInstanceError):
            req.tool_name = "hacked"  # type: ignore[misc]

    def test_to_dict(self) -> None:
        req = ToolRequest(
            tool_name="read_file",
            arguments={"path": "/tmp/x"},
            agent_id="a1",
            session_id="s1",
        )
        d = req.to_dict()
        assert d == {
            "tool_name": "read_file",
            "arguments": {"path": "/tmp/x"},
            "agent_id": "a1",
            "session_id": "s1",
        }


# ---------------------------------------------------------------------------
# PolicyDecision
# ---------------------------------------------------------------------------


class TestPolicyDecision:
    """PolicyDecision model tests."""

    def test_defaults(self) -> None:
        dec = PolicyDecision(action=PolicyAction.ALLOW, reason="ok")
        assert dec.rule_id is None
        assert dec.risk_level is RiskLevel.LOW

    def test_immutability(self) -> None:
        dec = PolicyDecision(action=PolicyAction.ALLOW, reason="ok")
        with pytest.raises(FrozenInstanceError):
            dec.action = PolicyAction.DENY  # type: ignore[misc]

    def test_serialization(self) -> None:
        dec = PolicyDecision(
            action=PolicyAction.DENY,
            reason="blocked",
            rule_id="r1",
            risk_level=RiskLevel.HIGH,
        )
        d = dec.to_dict()
        assert d["action"] == "DENY"
        assert d["risk_level"] == "HIGH"
        assert d["reason"] == "blocked"
        assert d["rule_id"] == "r1"

    def test_serialization_allow(self) -> None:
        dec = PolicyDecision(action=PolicyAction.ALLOW, reason="ok")
        d = dec.to_dict()
        assert d["action"] == "ALLOW"
        assert d["risk_level"] == "LOW"

    def test_serialization_require_approval(self) -> None:
        dec = PolicyDecision(
            action=PolicyAction.REQUIRE_APPROVAL,
            reason="needs approval",
            risk_level=RiskLevel.MEDIUM,
        )
        d = dec.to_dict()
        assert d["action"] == "REQUIRE_APPROVAL"
        assert d["risk_level"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    """PolicyAction and RiskLevel enum tests."""

    def test_policy_actions(self) -> None:
        assert set(PolicyAction) == {
            PolicyAction.ALLOW,
            PolicyAction.DENY,
            PolicyAction.REQUIRE_APPROVAL,
        }

    def test_risk_levels(self) -> None:
        assert set(RiskLevel) == {
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        }

    def test_action_values(self) -> None:
        assert PolicyAction.ALLOW.value == "ALLOW"
        assert PolicyAction.DENY.value == "DENY"
        assert PolicyAction.REQUIRE_APPROVAL.value == "REQUIRE_APPROVAL"


# ---------------------------------------------------------------------------
# Engine — default allow
# ---------------------------------------------------------------------------


class TestEngineDefaultAllow:
    """When no rule matches, the engine returns ALLOW."""

    def test_normal_tool_call(self) -> None:
        engine = _engine()
        req = ToolRequest(tool_name="list_files", arguments={"dir": "/tmp"})
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.ALLOW
        assert dec.risk_level is RiskLevel.LOW
        assert dec.rule_id is None

    def test_empty_engine(self) -> None:
        engine = PolicyEngine(rules=[])
        req = ToolRequest(tool_name="anything")
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.ALLOW

    def test_no_rules(self) -> None:
        engine = PolicyEngine()
        req = ToolRequest(tool_name="anything")
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.ALLOW

    def test_unrelated_shell_command(self) -> None:
        """A shell command that doesn't match 'rm -rf' should be allowed."""
        engine = _engine()
        req = ToolRequest(
            tool_name="shell",
            arguments={"command": "ls -la"},
        )
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.ALLOW


# ---------------------------------------------------------------------------
# Engine — DENY rules
# ---------------------------------------------------------------------------


class TestEngineDeny:
    """DENY rules from the default set."""

    def test_deny_shell_rm_rf(self) -> None:
        engine = _engine()
        req = ToolRequest(
            tool_name="shell",
            arguments={"command": "rm -rf /"},
        )
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.DENY
        assert dec.rule_id == "deny-shell-rm-rf"
        assert dec.risk_level is RiskLevel.CRITICAL

    def test_deny_read_env(self) -> None:
        engine = _engine()
        req = ToolRequest(
            tool_name="read_file",
            arguments={"path": ".env"},
        )
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.DENY
        assert dec.rule_id == "deny-read-env"
        assert dec.risk_level is RiskLevel.HIGH

    def test_deny_read_env_subdirectory(self) -> None:
        """Path containing '.env' anywhere should match."""
        engine = _engine()
        req = ToolRequest(
            tool_name="read_file",
            arguments={"path": "/app/.env.local"},
        )
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.DENY

    def test_deny_read_git_directory(self) -> None:
        engine = _engine()
        req = ToolRequest(
            tool_name="read_file",
            arguments={"path": ".git/config"},
        )
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.DENY
        assert dec.rule_id == "deny-read-git"

    def test_deny_read_git_subdirectory(self) -> None:
        engine = _engine()
        req = ToolRequest(
            tool_name="read_file",
            arguments={"path": ".git/refs/heads/main"},
        )
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.DENY

    def test_allow_gitignore(self) -> None:
        """'.gitignore' should NOT match the '.git/' regex."""
        engine = _engine()
        req = ToolRequest(
            tool_name="read_file",
            arguments={"path": ".gitignore"},
        )
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.ALLOW


# ---------------------------------------------------------------------------
# Engine — REQUIRE_APPROVAL rules
# ---------------------------------------------------------------------------


class TestEngineApproval:
    """REQUIRE_APPROVAL rules."""

    def test_force_push(self) -> None:
        engine = _engine()
        req = ToolRequest(tool_name="git_push_force")
        dec = engine.evaluate(req)
        assert dec.action is PolicyAction.REQUIRE_APPROVAL
        assert dec.rule_id == "approve-force-push"
        assert dec.risk_level is RiskLevel.HIGH


# ---------------------------------------------------------------------------
# Engine — priority & ordering
# ---------------------------------------------------------------------------


class TestEnginePriority:
    """Priority and declaration-order semantics."""

    def test_higher_priority_wins(self) -> None:
        """When two rules match, the higher-priority rule wins."""
        low = ToolNameRule(
            id="low",
            description="low",
            priority=10,
            tool_name="test",
            action=PolicyAction.ALLOW,
            risk_level=RiskLevel.LOW,
        )
        high = ToolNameRule(
            id="high",
            description="high",
            priority=100,
            tool_name="test",
            action=PolicyAction.DENY,
            risk_level=RiskLevel.HIGH,
        )
        # Pass low first — engine should still pick high.
        engine = PolicyEngine(rules=[low, high])
        dec = engine.evaluate(ToolRequest(tool_name="test"))
        assert dec.action is PolicyAction.DENY
        assert dec.rule_id == "high"

    def test_equal_priority_declaration_order(self) -> None:
        """When priorities are equal, the first-declared rule wins."""
        first = ToolNameRule(
            id="first",
            description="first",
            priority=50,
            tool_name="test",
            action=PolicyAction.DENY,
            risk_level=RiskLevel.HIGH,
        )
        second = ToolNameRule(
            id="second",
            description="second",
            priority=50,
            tool_name="test",
            action=PolicyAction.REQUIRE_APPROVAL,
            risk_level=RiskLevel.MEDIUM,
        )
        engine = PolicyEngine(rules=[first, second])
        dec = engine.evaluate(ToolRequest(tool_name="test"))
        assert dec.rule_id == "first"
        assert dec.action is PolicyAction.DENY


# ---------------------------------------------------------------------------
# Engine — fail-closed on rule errors
# ---------------------------------------------------------------------------


class TestEngineFailClosed:
    """A buggy rule should fail closed (DENY) rather than crash or allow."""

    def test_rule_exception_fails_closed(self) -> None:
        class BrokenRule(PolicyRule):
            def matches(self, request: ToolRequest) -> bool:
                raise RuntimeError("bug in rule")

        broken = BrokenRule(id="broken", description="broken rule", priority=100)
        engine = PolicyEngine(rules=[broken])
        dec = engine.evaluate(ToolRequest(tool_name="anything"))
        assert dec.action is PolicyAction.DENY
        assert dec.risk_level is RiskLevel.CRITICAL
        assert dec.rule_id == "broken"
        assert "evaluation error" in dec.reason

    def test_broken_rule_does_not_crash_engine(self) -> None:
        """The engine must return a decision, never raise."""

        class BrokenRule(PolicyRule):
            def matches(self, request: ToolRequest) -> bool:
                raise ValueError("oops")

        broken = BrokenRule(id="bad", description="bad", priority=200)
        safe = ToolNameRule(
            id="safe",
            description="safe",
            priority=10,
            tool_name="test",
            action=PolicyAction.ALLOW,
            risk_level=RiskLevel.LOW,
        )
        engine = PolicyEngine(rules=[broken, safe])
        # The broken rule is evaluated first (higher priority) and should
        # cause a DENY rather than letting the safe rule through.
        dec = engine.evaluate(ToolRequest(tool_name="test"))
        assert dec.action is PolicyAction.DENY
        assert dec.rule_id == "bad"


# ---------------------------------------------------------------------------
# Individual rule types
# ---------------------------------------------------------------------------


class TestToolNameRule:
    """ToolNameRule matching."""

    def test_matches(self) -> None:
        rule = ToolNameRule(id="r", description="d", tool_name="shell")
        assert rule.matches(ToolRequest(tool_name="shell"))
        assert not rule.matches(ToolRequest(tool_name="read_file"))


class TestArgumentPatternRule:
    """ArgumentPatternRule matching."""

    def test_substring_match(self) -> None:
        rule = ArgumentPatternRule(
            id="r",
            description="d",
            tool_name="read_file",
            argument="path",
            pattern=".env",
        )
        assert rule.matches(
            ToolRequest(tool_name="read_file", arguments={"path": ".env"})
        )
        assert not rule.matches(
            ToolRequest(tool_name="read_file", arguments={"path": "README.md"})
        )

    def test_regex_match(self) -> None:
        rule = ArgumentPatternRule(
            id="r",
            description="d",
            tool_name="read_file",
            argument="path",
            pattern=r"^\.git/",
            is_regex=True,
        )
        assert rule.matches(
            ToolRequest(tool_name="read_file", arguments={"path": ".git/config"})
        )
        assert not rule.matches(
            ToolRequest(tool_name="read_file", arguments={"path": ".gitignore"})
        )

    def test_wrong_tool(self) -> None:
        rule = ArgumentPatternRule(
            id="r",
            description="d",
            tool_name="read_file",
            argument="path",
            pattern=".env",
        )
        assert not rule.matches(
            ToolRequest(tool_name="write_file", arguments={"path": ".env"})
        )

    def test_missing_argument(self) -> None:
        rule = ArgumentPatternRule(
            id="r",
            description="d",
            tool_name="shell",
            argument="command",
            pattern="rm",
        )
        assert not rule.matches(
            ToolRequest(tool_name="shell", arguments={})
        )

    def test_any_tool_name(self) -> None:
        """Empty tool_name should match any tool."""
        rule = ArgumentPatternRule(
            id="r",
            description="d",
            tool_name="",
            argument="path",
            pattern="secret",
        )
        assert rule.matches(
            ToolRequest(tool_name="read_file", arguments={"path": "secret.txt"})
        )
        assert rule.matches(
            ToolRequest(tool_name="write_file", arguments={"path": "secret.txt"})
        )

    def test_non_string_argument_value(self) -> None:
        """Non-string argument values should be converted to string."""
        rule = ArgumentPatternRule(
            id="r",
            description="d",
            argument="count",
            pattern="42",
        )
        assert rule.matches(
            ToolRequest(tool_name="test", arguments={"count": 42})
        )


class TestApprovalRule:
    """ApprovalRule matching."""

    def test_matches(self) -> None:
        rule = ApprovalRule(
            id="r",
            description="d",
            tool_name="git_push_force",
        )
        assert rule.matches(ToolRequest(tool_name="git_push_force"))
        assert not rule.matches(ToolRequest(tool_name="git_push"))

    def test_default_action(self) -> None:
        rule = ApprovalRule(id="r", description="d", tool_name="x")
        assert rule.action is PolicyAction.REQUIRE_APPROVAL
        assert rule.risk_level is RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# Public API imports
# ---------------------------------------------------------------------------


class TestPublicAPI:
    """Verify the public API surface from agentguard.policy."""

    def test_imports(self) -> None:
        from agentguard.policy import (  # noqa: F401
            ApprovalRule,
            ArgumentPatternRule,
            PolicyAction,
            PolicyDecision,
            PolicyEngine,
            RiskLevel,
            ToolNameRule,
            ToolRequest,
        )

    def test_end_to_end(self) -> None:
        """Full end-to-end usage example."""
        engine = PolicyEngine(rules=list(DEFAULT_RULES))

        # ALLOW
        allow = engine.evaluate(
            ToolRequest(tool_name="list_files", arguments={"dir": "/tmp"})
        )
        assert allow.action is PolicyAction.ALLOW

        # DENY
        deny = engine.evaluate(
            ToolRequest(tool_name="read_file", arguments={"path": ".env"})
        )
        assert deny.action is PolicyAction.DENY

        # REQUIRE_APPROVAL
        approval = engine.evaluate(ToolRequest(tool_name="git_push_force"))
        assert approval.action is PolicyAction.REQUIRE_APPROVAL
