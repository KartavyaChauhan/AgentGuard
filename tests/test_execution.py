"""Comprehensive tests for the execution / enforcement pipeline.

Security-critical invariants are tested with side-effect counters to prove
tools are never invoked when the policy says DENY or REQUIRE_APPROVAL.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from agentguard.execution import ExecutionResult, ExecutionStatus, ToolExecutor
from agentguard.policy import (
    PolicyAction,
    PolicyDecision,
    PolicyEngine,
    RiskLevel,
    ToolRequest,
)
from agentguard.policy.defaults import DEFAULT_RULES
from agentguard.policy.rules import ApprovalRule, ArgumentPatternRule, ToolNameRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_executor(
    tools: dict | None = None,
    rules: list | None = None,
) -> ToolExecutor:
    """Create an executor with the default demo rules and given tools."""
    engine = PolicyEngine(rules=list(rules if rules is not None else DEFAULT_RULES))
    return ToolExecutor(policy_engine=engine, tools=tools or {})


class _CallCounter:
    """A callable that counts invocations — used to prove enforcement."""

    def __init__(self, return_value: object = None) -> None:
        self.count = 0
        self.return_value = return_value

    def __call__(self, **kwargs: object) -> object:
        self.count += 1
        return self.return_value


# ---------------------------------------------------------------------------
# ExecutionResult model
# ---------------------------------------------------------------------------


class TestExecutionResult:
    """ExecutionResult model tests."""

    def test_immutability(self) -> None:
        result = ExecutionResult(
            status=ExecutionStatus.EXECUTED,
            decision=PolicyDecision(action=PolicyAction.ALLOW, reason="ok"),
            output=42,
        )
        with pytest.raises(FrozenInstanceError):
            result.status = ExecutionStatus.FAILED  # type: ignore[misc]

    def test_serialization(self) -> None:
        result = ExecutionResult(
            status=ExecutionStatus.DENIED,
            decision=PolicyDecision(
                action=PolicyAction.DENY,
                reason="blocked",
                rule_id="r1",
                risk_level=RiskLevel.HIGH,
            ),
            error="not allowed",
        )
        d = result.to_dict()
        assert d["status"] == "DENIED"
        assert d["decision"]["action"] == "DENY"
        assert d["decision"]["risk_level"] == "HIGH"
        assert d["error"] == "not allowed"
        assert d["output"] is None
        assert d["duration_ms"] is None

    def test_serialization_executed(self) -> None:
        result = ExecutionResult(
            status=ExecutionStatus.EXECUTED,
            decision=PolicyDecision(action=PolicyAction.ALLOW, reason="ok"),
            output={"files": ["a.txt"]},
            duration_ms=12.5,
        )
        d = result.to_dict()
        assert d["status"] == "EXECUTED"
        assert d["output"] == {"files": ["a.txt"]}
        assert d["duration_ms"] == 12.5


class TestExecutionStatus:
    """ExecutionStatus enum tests."""

    def test_all_statuses(self) -> None:
        assert set(ExecutionStatus) == {
            ExecutionStatus.EXECUTED,
            ExecutionStatus.DENIED,
            ExecutionStatus.APPROVAL_REQUIRED,
            ExecutionStatus.FAILED,
        }

    def test_values(self) -> None:
        assert ExecutionStatus.EXECUTED.value == "EXECUTED"
        assert ExecutionStatus.DENIED.value == "DENIED"
        assert ExecutionStatus.APPROVAL_REQUIRED.value == "APPROVAL_REQUIRED"
        assert ExecutionStatus.FAILED.value == "FAILED"


# ---------------------------------------------------------------------------
# ToolExecutor — ALLOW → executes
# ---------------------------------------------------------------------------


class TestExecutorAllow:
    """When policy says ALLOW, the tool must execute."""

    def test_simple_tool_executes(self) -> None:
        def add(a: int, b: int) -> int:
            return a + b

        executor = _make_executor(tools={"add": add})
        result = executor.execute(
            ToolRequest(tool_name="add", arguments={"a": 2, "b": 3})
        )
        assert result.status is ExecutionStatus.EXECUTED
        assert result.output == 5
        assert result.error is None
        assert result.decision.action is PolicyAction.ALLOW

    def test_execution_has_duration(self) -> None:
        counter = _CallCounter(return_value="ok")
        executor = _make_executor(tools={"ping": counter})
        result = executor.execute(ToolRequest(tool_name="ping"))
        assert result.status is ExecutionStatus.EXECUTED
        assert result.duration_ms is not None
        assert result.duration_ms >= 0

    def test_tool_with_no_arguments(self) -> None:
        def noop() -> str:
            return "done"

        executor = _make_executor(tools={"noop": noop})
        result = executor.execute(ToolRequest(tool_name="noop"))
        assert result.status is ExecutionStatus.EXECUTED
        assert result.output == "done"

    def test_counter_increments_on_allow(self) -> None:
        counter = _CallCounter(return_value=42)
        executor = _make_executor(tools={"safe": counter})
        executor.execute(ToolRequest(tool_name="safe"))
        assert counter.count == 1

    def test_unrelated_shell_command_executes(self) -> None:
        """A shell command not matching 'rm -rf' should be allowed."""
        counter = _CallCounter(return_value="ok")
        executor = _make_executor(tools={"shell": counter})
        result = executor.execute(
            ToolRequest(tool_name="shell", arguments={"command": "ls -la"})
        )
        assert result.status is ExecutionStatus.EXECUTED
        assert counter.count == 1


# ---------------------------------------------------------------------------
# ToolExecutor — DENY → tool does NOT execute
# ---------------------------------------------------------------------------


class TestExecutorDeny:
    """When policy says DENY, the tool must NEVER execute."""

    def test_deny_does_not_execute(self) -> None:
        counter = _CallCounter()
        executor = _make_executor(tools={"read_file": counter})
        result = executor.execute(
            ToolRequest(tool_name="read_file", arguments={"path": ".env"})
        )
        assert result.status is ExecutionStatus.DENIED
        assert counter.count == 0  # ← enforcement proof
        assert result.decision.action is PolicyAction.DENY
        assert result.output is None
        assert result.duration_ms is None

    def test_deny_preserves_decision(self) -> None:
        counter = _CallCounter()
        executor = _make_executor(tools={"read_file": counter})
        result = executor.execute(
            ToolRequest(tool_name="read_file", arguments={"path": ".env"})
        )
        assert result.decision.rule_id == "deny-read-env"
        assert result.decision.risk_level is RiskLevel.HIGH

    def test_deny_env_read_blocked(self) -> None:
        """Security invariant: .env reads are blocked."""
        counter = _CallCounter()
        executor = _make_executor(tools={"read_file": counter})
        result = executor.execute(
            ToolRequest(tool_name="read_file", arguments={"path": ".env"})
        )
        assert result.status is ExecutionStatus.DENIED
        assert counter.count == 0

    def test_deny_rm_rf_blocked(self) -> None:
        """Security invariant: rm -rf is blocked."""
        counter = _CallCounter()
        executor = _make_executor(tools={"shell": counter})
        result = executor.execute(
            ToolRequest(
                tool_name="shell",
                arguments={"command": "rm -rf /"},
            )
        )
        assert result.status is ExecutionStatus.DENIED
        assert counter.count == 0
        assert result.decision.rule_id == "deny-shell-rm-rf"
        assert result.decision.risk_level is RiskLevel.CRITICAL

    def test_deny_git_directory_blocked(self) -> None:
        """Security invariant: .git/ reads are blocked."""
        counter = _CallCounter()
        executor = _make_executor(tools={"read_file": counter})
        result = executor.execute(
            ToolRequest(
                tool_name="read_file",
                arguments={"path": ".git/config"},
            )
        )
        assert result.status is ExecutionStatus.DENIED
        assert counter.count == 0


# ---------------------------------------------------------------------------
# ToolExecutor — REQUIRE_APPROVAL → tool does NOT execute
# ---------------------------------------------------------------------------


class TestExecutorApproval:
    """When policy says REQUIRE_APPROVAL, the tool must NOT execute."""

    def test_approval_does_not_execute(self) -> None:
        counter = _CallCounter()
        executor = _make_executor(tools={"git_push_force": counter})
        result = executor.execute(ToolRequest(tool_name="git_push_force"))
        assert result.status is ExecutionStatus.APPROVAL_REQUIRED
        assert counter.count == 0  # ← enforcement proof
        assert result.decision.action is PolicyAction.REQUIRE_APPROVAL
        assert result.output is None
        assert result.duration_ms is None

    def test_approval_preserves_decision(self) -> None:
        counter = _CallCounter()
        executor = _make_executor(tools={"git_push_force": counter})
        result = executor.execute(ToolRequest(tool_name="git_push_force"))
        assert result.decision.rule_id == "approve-force-push"
        assert result.decision.risk_level is RiskLevel.HIGH


# ---------------------------------------------------------------------------
# ToolExecutor — unknown tool
# ---------------------------------------------------------------------------


class TestExecutorUnknownTool:
    """If the tool doesn't exist, the executor returns FAILED."""

    def test_unknown_tool_fails(self) -> None:
        executor = _make_executor(tools={})
        result = executor.execute(ToolRequest(tool_name="nonexistent"))
        assert result.status is ExecutionStatus.FAILED
        assert result.error is not None
        assert "nonexistent" in result.error
        assert result.output is None

    def test_unknown_tool_still_has_allow_decision(self) -> None:
        """Policy evaluated first and allowed, but tool not found."""
        executor = _make_executor(tools={})
        result = executor.execute(ToolRequest(tool_name="nonexistent"))
        assert result.decision.action is PolicyAction.ALLOW


# ---------------------------------------------------------------------------
# ToolExecutor — tool raises exception
# ---------------------------------------------------------------------------


class TestExecutorToolException:
    """If the tool raises, the executor returns FAILED safely."""

    def test_tool_exception_returns_failed(self) -> None:
        def exploding_tool() -> None:
            raise RuntimeError("kaboom")

        executor = _make_executor(tools={"boom": exploding_tool})
        result = executor.execute(ToolRequest(tool_name="boom"))
        assert result.status is ExecutionStatus.FAILED
        assert result.error is not None
        assert "kaboom" in result.error
        assert result.output is None

    def test_tool_exception_has_duration(self) -> None:
        def exploding_tool() -> None:
            raise ValueError("oops")

        executor = _make_executor(tools={"boom": exploding_tool})
        result = executor.execute(ToolRequest(tool_name="boom"))
        assert result.duration_ms is not None
        assert result.duration_ms >= 0

    def test_tool_exception_does_not_expose_traceback(self) -> None:
        def exploding_tool() -> None:
            raise RuntimeError("secret details")

        executor = _make_executor(tools={"boom": exploding_tool})
        result = executor.execute(ToolRequest(tool_name="boom"))
        # error should contain the message but not a full traceback
        assert "Traceback" not in (result.error or "")
        assert "secret details" in (result.error or "")


# ---------------------------------------------------------------------------
# Policy evaluated BEFORE tool lookup/execution
# ---------------------------------------------------------------------------


class TestPolicyBeforeExecution:
    """Prove the policy is always evaluated before the tool is looked up."""

    def test_deny_even_if_tool_not_registered(self) -> None:
        """If the policy denies, the tool name doesn't even need to exist."""
        executor = _make_executor(tools={})  # no tools registered at all
        result = executor.execute(
            ToolRequest(tool_name="read_file", arguments={"path": ".env"})
        )
        # Must be DENIED, not FAILED (tool-not-found).
        assert result.status is ExecutionStatus.DENIED
        assert result.decision.action is PolicyAction.DENY

    def test_approval_even_if_tool_not_registered(self) -> None:
        executor = _make_executor(tools={})
        result = executor.execute(ToolRequest(tool_name="git_push_force"))
        assert result.status is ExecutionStatus.APPROVAL_REQUIRED

    def test_deny_prevents_any_side_effect(self) -> None:
        """Counter must stay at zero even though the tool is registered."""
        counter = _CallCounter()
        deny_rule = ToolNameRule(
            id="deny-all-test",
            description="deny everything",
            priority=999,
            tool_name="test",
            action=PolicyAction.DENY,
            risk_level=RiskLevel.HIGH,
        )
        executor = _make_executor(tools={"test": counter}, rules=[deny_rule])
        executor.execute(ToolRequest(tool_name="test"))
        assert counter.count == 0


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


class TestToolRegistration:
    """ToolExecutor tool registry helpers."""

    def test_register_tool(self) -> None:
        executor = _make_executor()
        executor.register_tool("ping", lambda: "pong")
        assert "ping" in executor.tool_names

    def test_tool_names_empty(self) -> None:
        executor = _make_executor()
        assert executor.tool_names == []


# ---------------------------------------------------------------------------
# Public API imports
# ---------------------------------------------------------------------------


class TestPublicAPI:
    """Verify the public API surface from agentguard.execution."""

    def test_imports(self) -> None:
        from agentguard.execution import (  # noqa: F401
            ExecutionResult,
            ExecutionStatus,
            ToolExecutor,
        )

    def test_end_to_end(self) -> None:
        """Full end-to-end pipeline: request → policy → execute → result."""
        def add(a: int, b: int) -> int:
            return a + b

        engine = PolicyEngine(rules=list(DEFAULT_RULES))
        executor = ToolExecutor(policy_engine=engine, tools={"add": add})

        # EXECUTED
        r1 = executor.execute(
            ToolRequest(tool_name="add", arguments={"a": 10, "b": 20})
        )
        assert r1.status is ExecutionStatus.EXECUTED
        assert r1.output == 30

        # DENIED
        r2 = executor.execute(
            ToolRequest(tool_name="read_file", arguments={"path": ".env"})
        )
        assert r2.status is ExecutionStatus.DENIED

        # APPROVAL_REQUIRED
        r3 = executor.execute(ToolRequest(tool_name="git_push_force"))
        assert r3.status is ExecutionStatus.APPROVAL_REQUIRED
