import functools
import inspect
from typing import Any, Callable

from agentguard.execution.executor import ToolExecutor
from agentguard.execution.models import ExecutionStatus
from agentguard.policy.models import ToolRequest


class AgentGuardError(Exception):
    """Exception raised when AgentGuard blocks a tool execution."""
    pass


class MCPAdapter:
    """Adapts MCP tool invocations to AgentGuard ToolRequests."""

    def __init__(self, executor: ToolExecutor):
        self._executor = executor

    def wrap_tool(self, tool_fn: Callable[..., Any]) -> Callable[..., Any]:
        """
        Wrap a tool function so that it routes through AgentGuard's execution layer.
        Preserves the function signature so the MCP server can generate the JSON schema.
        """
        tool_name = tool_fn.__name__

        @functools.wraps(tool_fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if args:
                raise ValueError("AgentGuard MCP adapter expects keyword arguments only.")

            request = ToolRequest(tool_name=tool_name, arguments=kwargs)
            result = self._executor.execute(request)

            if result.status == ExecutionStatus.EXECUTED:
                # If the underlying tool was an async function, the executor returned a coroutine.
                # Returning it here allows the caller (MCP Server) to await it.
                return result.output
            elif result.status == ExecutionStatus.DENIED:
                raise AgentGuardError(f"AgentGuard denied execution: {result.decision.reason}")
            elif result.status == ExecutionStatus.APPROVAL_REQUIRED:
                raise AgentGuardError(f"AgentGuard requires approval: {result.decision.reason}")
            elif result.status == ExecutionStatus.FAILED:
                if result.error:
                    raise AgentGuardError(f"Execution failed: {result.error}")
                raise AgentGuardError("Execution failed for an unknown reason.")

            raise AgentGuardError(f"Unexpected execution status: {result.status}")

        return wrapper
