import pytest

from agentguard.policy.engine import PolicyEngine
from agentguard.policy.rules import ToolNameRule, ArgumentPatternRule, ApprovalRule
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.executor import ToolExecutor
from agentguard.mcp.adapter import MCPAdapter, AgentGuardError
from agentguard.mcp.server import create_demo_server


class _CallCounter:
    def __init__(self):
        self.count = 0
        self.last_kwargs = None

    def __call__(self, **kwargs):
        self.count += 1
        self.last_kwargs = kwargs
        return "success"


@pytest.fixture
def policy_engine():
    return PolicyEngine(rules=[
        ToolNameRule(
            id="deny-env",
            description="Deny reading .env files",
            action=PolicyAction.DENY,
            risk_level=RiskLevel.HIGH,
            priority=100,
            tool_name="read_file",
        ),
        ApprovalRule(
            id="approve-force-push",
            description="Force push requires approval",
            action=PolicyAction.REQUIRE_APPROVAL,
            risk_level=RiskLevel.MEDIUM,
            priority=100,
            tool_name="git_push_force",
        )
    ])


@pytest.fixture
def executor(policy_engine):
    return ToolExecutor(policy_engine=policy_engine)


@pytest.fixture
def adapter(executor):
    return MCPAdapter(executor)


class TestMCPAdapter:
    def test_allowed_tool_executes(self, executor, adapter):
        counter = _CallCounter()
        counter.__name__ = "calculate"
        executor.register_tool("calculate", counter)

        # Wrap the tool
        wrapped = adapter.wrap_tool(counter)
        
        # It's an allowed tool (default engine policy is allow if no rules match)
        result = wrapped(a=1, b=2)
        
        assert result == "success"
        assert counter.count == 1
        assert counter.last_kwargs == {"a": 1, "b": 2}

    def test_denied_tool_blocked(self, executor, adapter, policy_engine):
        counter = _CallCounter()
        
        # We explicitly mock the name because wrapper relies on __name__
        counter.__name__ = "read_file"
        executor.register_tool("read_file", counter)

        wrapped = adapter.wrap_tool(counter)
        
        # read_file is DENIED by our fixture engine
        with pytest.raises(AgentGuardError, match="AgentGuard denied execution"):
            wrapped(path=".env")
            
        assert counter.count == 0

    def test_approval_required_blocked(self, executor, adapter):
        counter = _CallCounter()
        counter.__name__ = "git_push_force"
        executor.register_tool("git_push_force", counter)

        wrapped = adapter.wrap_tool(counter)
        
        # git_push_force is REQUIRE_APPROVAL by our fixture
        with pytest.raises(AgentGuardError, match="AgentGuard requires approval"):
            wrapped()
            
        assert counter.count == 0

    def test_positional_args_rejected(self, adapter):
        def my_tool(x):
            pass
            
        wrapped = adapter.wrap_tool(my_tool)
        
        # MCP uses keyword args (JSON-RPC). The adapter rejects positional.
        with pytest.raises(ValueError, match="expects keyword arguments only"):
            wrapped(1)


class TestMCPServerIntegration:
    def test_demo_server_creation(self, policy_engine, executor):
        # The demo server should build correctly and bind the tools
        server = create_demo_server(policy_engine, executor)
        assert server.name == "AgentGuard Demo Server"
        
        # We can also verify that we can retrieve the tools list (which MCPServer provides async)
        # Note: server.list_tools() is available in mcp>=2.0
        # Since this test is sync, we just ensure it didn't crash on creation.
        # MCPServer adds tools to its internal manager.
        assert len(executor.tool_names) == 4
        assert "list_files" in executor.tool_names
        assert "read_file" in executor.tool_names
        assert "calculate" in executor.tool_names
        assert "git_push_force" in executor.tool_names
