"""Tool execution with policy enforcement.

The :class:`ToolExecutor` is the enforcement boundary.  It evaluates every
:class:`~agentguard.policy.models.ToolRequest` against a
:class:`~agentguard.policy.engine.PolicyEngine` **before** the tool is looked
up or invoked.  Only ``ALLOW`` decisions result in actual execution.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, TYPE_CHECKING
from datetime import datetime, timezone
import uuid

from agentguard.logging import get_logger
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.models import PolicyAction, PolicyDecision, RiskLevel, ToolRequest
from agentguard.execution.models import ExecutionResult, ExecutionStatus

if TYPE_CHECKING:
    from agentguard.events.store import EventStore

logger = get_logger(__name__)

# Type alias for a tool callable.  Tools receive keyword arguments drawn
# from ``ToolRequest.arguments``.
ToolCallable = Callable[..., Any]


class ToolExecutor:
    """Enforce policy decisions and execute permitted tool calls.

    Parameters
    ----------
    policy_engine:
        The policy engine used to evaluate every request.
    tools:
        A mapping of tool names to Python callables.  Each callable is
        invoked with ``**request.arguments`` when allowed.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        tools: dict[str, ToolCallable] | None = None,
        event_store: EventStore | None = None,
    ) -> None:
        self._engine = policy_engine
        self._tools: dict[str, ToolCallable] = dict(tools or {})
        self._event_store = event_store

    # ------------------------------------------------------------------
    # Tool registry helpers
    # ------------------------------------------------------------------

    def register_tool(self, name: str, fn: ToolCallable) -> None:
        """Register a tool callable under *name*."""
        self._tools[name] = fn

    @property
    def tool_names(self) -> list[str]:
        """Return the names of all registered tools."""
        return list(self._tools)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(self, request: ToolRequest) -> ExecutionResult:
        """Evaluate *request* against the policy engine and, if allowed, run the tool.

        The policy is **always** evaluated before the tool is looked up or
        called.  This guarantees the enforcement boundary cannot be bypassed.

        Returns
        -------
        ExecutionResult
            An immutable result describing what happened.
        """
        # 1. Evaluate policy FIRST — before any tool lookup.
        decision: PolicyDecision = self._engine.evaluate(request)
        
        result: ExecutionResult
        
        # 2. DENY — do not execute.
        if decision.action is PolicyAction.DENY:
            logger.info(
                "Tool execution denied",
                extra={
                    "tool": request.tool_name,
                    "rule_id": decision.rule_id,
                },
            )
            result = ExecutionResult(
                status=ExecutionStatus.DENIED,
                decision=decision,
            )

        # 3. REQUIRE_APPROVAL — do not execute.
        elif decision.action is PolicyAction.REQUIRE_APPROVAL:
            logger.info(
                "Tool execution requires approval",
                extra={
                    "tool": request.tool_name,
                    "rule_id": decision.rule_id,
                },
            )
            result = ExecutionResult(
                status=ExecutionStatus.APPROVAL_REQUIRED,
                decision=decision,
            )

        else:
            # 4. ALLOW — look up the tool.
            fn = self._tools.get(request.tool_name)
            if fn is None:
                logger.warning(
                    "Tool not found",
                    extra={"tool": request.tool_name},
                )
                result = ExecutionResult(
                    status=ExecutionStatus.FAILED,
                    decision=decision,
                    error=f"Unknown tool: '{request.tool_name}'",
                )
            else:
                # 5. Execute the tool, measuring wall-clock time.
                start = time.monotonic()
                try:
                    output = fn(**request.arguments)
                except Exception as exc:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    logger.exception(
                        "Tool execution failed",
                        extra={"tool": request.tool_name},
                    )
                    result = ExecutionResult(
                        status=ExecutionStatus.FAILED,
                        decision=decision,
                        error=f"Tool '{request.tool_name}' raised an error: {exc}",
                        duration_ms=elapsed_ms,
                    )
                else:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    logger.info(
                        "Tool executed successfully",
                        extra={
                            "tool": request.tool_name,
                            "duration_ms": round(elapsed_ms, 2),
                        },
                    )
                    result = ExecutionResult(
                        status=ExecutionStatus.EXECUTED,
                        decision=decision,
                        output=output,
                        duration_ms=elapsed_ms,
                    )

        # Record the event if an event store is provided
        if self._event_store is not None:
            # If request.session_id is missing, generate one for the event to ensure isolation,
            # but do not mutate the original ToolRequest.
            session_id = request.session_id if request.session_id is not None else uuid.uuid4().hex

            from agentguard.events.models import ToolEvent

            event = ToolEvent(
                event_id=uuid.uuid4().hex,
                timestamp=datetime.now(timezone.utc),
                session_id=session_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                arguments=request.arguments,  # ToolEvent defensively copies this
                policy_action=decision.action,
                risk_level=decision.risk_level,
                execution_status=result.status,
                rule_id=decision.rule_id,
                duration_ms=result.duration_ms,
            )
            self._event_store.record(event)

        return result
