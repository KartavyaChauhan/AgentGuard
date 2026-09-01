"""Synthetic agent for benchmark."""

import uuid
from typing import Dict, Any, Callable
from agentguard.policy.models import ToolRequest, PolicyAction
from agentguard.execution.executor import ToolExecutor
from agentguard.execution.models import ExecutionResult, ExecutionStatus
from agentguard.events.models import ToolEvent


class SyntheticAgent:
    """A synthetic agent with simulated tools that returns deterministic responses."""

    def __init__(self, use_guard: bool = False, policy_engine=None, event_store=None, executor: ToolExecutor = None):
        self.use_guard = use_guard
        self.policy_engine = policy_engine
        self.event_store = event_store
        
        from agentguard.policy.engine import PolicyEngine
        if self.use_guard:
            self.executor = executor or ToolExecutor(policy_engine=self.policy_engine or PolicyEngine(), event_store=self.event_store)
        else:
            self.executor = executor or ToolExecutor(policy_engine=PolicyEngine(), event_store=None)
        
        # Register the simulated tools
        self._register_mock_tools()

    def _register_mock_tools(self):
        def _mock_read_file(path: str = "") -> str:
            return "mock file content"
            
        def _mock_write_file(path: str = "", content: str = "") -> str:
            return "mock file written"
            
        def _mock_shell(command: str = "") -> str:
            return "mock shell output"
            
        def _mock_http_request(url: str = "") -> str:
            return "mock http response"
            
        def _mock_base64_encode(data: str = "") -> str:
            return "mock base64"
            
        def _mock_git_push(force: bool = False) -> str:
            return "mock push success"
            
        def _mock_run_tests(test_status: str = "passed") -> str:
            return f"tests {test_status}"
            
        def _mock_sudo(command: str = "") -> str:
            return "mock sudo output"
            
        def _mock_edit_file(path: str = "", content: str = "") -> str:
            return "mock file edited"

        # Register tools in executor
        tools = {
            "read_file": _mock_read_file,
            "write_file": _mock_write_file,
            "shell": _mock_shell,
            "http_request": _mock_http_request,
            "base64_encode": _mock_base64_encode,
            "git_push": _mock_git_push,
            "run_tests": _mock_run_tests,
            "sudo": _mock_sudo,
            "edit_file": _mock_edit_file,
        }
        
        for name, func in tools.items():
            self.executor.register_tool(name, func)

    def execute_tool(self, session_id: str, tool_name: str, arguments: Dict[str, Any]) -> tuple[str, bool]:
        """
        Executes a tool call.
        Returns:
            Tuple[str, bool]: (status string, blocked boolean)
        """
        request = ToolRequest(tool_name=tool_name, arguments=arguments, session_id=session_id)
        
        # ToolExecutor handles policy evaluation, execution, and event tracking
        result = self.executor.execute(request)
        
        if result.status in (ExecutionStatus.DENIED, ExecutionStatus.APPROVAL_REQUIRED):
            return ("BLOCKED", True)
        if result.status == ExecutionStatus.FAILED:
            return ("FAILED", False)
        return ("COMPLETED", False)
