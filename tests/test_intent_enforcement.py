import pytest
from unittest.mock import AsyncMock

from agentguard.intent.models import TaskIntent, IntentConstraint
from agentguard.intent.capabilities import Capability
from agentguard.intent.enforcement import IntentEnforcer
from agentguard.policy.models import ToolRequest, PolicyAction, PolicyDecision, RiskLevel
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.rules import ToolNameRule
from agentguard.context.models import SecurityContext
from agentguard.gateway.proxy import AgentGuardGateway

pytestmark = pytest.mark.anyio


@pytest.fixture
def mock_client_session():
    session = AsyncMock()
    
    # Mock list_tools
    class MockTool:
        def __init__(self, name):
            self.name = name
            self.description = "A mock tool"
            self.inputSchema = {"type": "object"}
            
    class MockListResult:
        tools = [MockTool("mock_tool"), MockTool("pytest"), MockTool("http_request"), MockTool("read_file")]
        
    session.list_tools.return_value = MockListResult()
    
    # Mock call_tool
    class MockContent:
        type = "text"
        text = "Mock tool output"
        
    class MockCallResult:
        content = [MockContent()]
        is_error = False
        
    session.call_tool.return_value = MockCallResult()
    return session


def test_intent_enforcer_no_intent():
    enforcer = IntentEnforcer(intent=None)
    request = ToolRequest("http_request", {})
    assert enforcer.evaluate(request) is None


def test_intent_enforcer_allowed():
    intent = TaskIntent(
        intent_id="id",
        description="desc",
        allowed_capabilities=(Capability.NETWORK,),
        forbidden_capabilities=()
    )
    enforcer = IntentEnforcer(intent)
    request = ToolRequest("http_request", {"url": "http://example.com"})
    assert enforcer.evaluate(request) is None


def test_intent_enforcer_forbidden():
    intent = TaskIntent(
        intent_id="id",
        description="desc",
        allowed_capabilities=(),
        forbidden_capabilities=(Capability.NETWORK,)
    )
    enforcer = IntentEnforcer(intent)
    request = ToolRequest("http_request", {})
    
    decision = enforcer.evaluate(request)
    assert decision is not None
    assert decision.action == PolicyAction.DENY
    assert "not authorized" in decision.reason
    assert decision.risk_level == RiskLevel.CRITICAL


def test_intent_enforcer_unclassified_denied():
    intent = TaskIntent(
        intent_id="id",
        description="desc",
        allowed_capabilities=(Capability.NETWORK,),
        forbidden_capabilities=()
    )
    enforcer = IntentEnforcer(intent)
    request = ToolRequest("some_random_tool", {})
    
    decision = enforcer.evaluate(request)
    assert decision is not None
    assert decision.action == PolicyAction.DENY
    assert "unknown capability" in decision.reason
    assert decision.risk_level == RiskLevel.CRITICAL


async def test_gateway_intent_blocking_prevents_upstream(mock_client_session):
    # Setup intent that forbids NETWORK
    intent = TaskIntent(
        intent_id="test",
        description="test",
        allowed_capabilities=(Capability.TEST_EXECUTION,),
        forbidden_capabilities=(Capability.NETWORK,)
    )
    context = SecurityContext(session_id="s1", agent_id="a1", active_intent=intent)
    
    # Setup policy engine that allows everything
    engine = PolicyEngine(rules=[])
    gateway = AgentGuardGateway(mock_client_session, engine, security_context=context)
    
    # Register tools
    await gateway.server._request_handlers["tools/list"].handler(None, None)
    
    # 1. Test allowed capability (TEST_EXECUTION -> pytest)
    import mcp.types as types
    req1 = types.CallToolRequestParams(name="pytest", arguments={})
    res1 = await gateway.server._request_handlers["tools/call"].handler(None, req1)
    
    assert not res1.is_error
    assert mock_client_session.call_tool.call_count == 1
    
    # 2. Test forbidden capability (NETWORK -> http_request)
    req2 = types.CallToolRequestParams(name="http_request", arguments={})
    res2 = await gateway.server._request_handlers["tools/call"].handler(None, req2)
    
    # Upstream should NOT be called again
    assert mock_client_session.call_tool.call_count == 1
    
    assert res2.is_error
    assert "not authorized by the active TaskIntent" in res2.content[0].text


async def test_gateway_intent_allow_falls_back_to_policy_deny(mock_client_session):
    # Setup intent that ALLOWS NETWORK
    intent = TaskIntent(
        intent_id="test",
        description="test",
        allowed_capabilities=(Capability.NETWORK,),
        forbidden_capabilities=()
    )
    context = SecurityContext(session_id="s1", agent_id="a1", active_intent=intent)
    
    # Setup policy engine that explicitly DENIES http_request
    rule = ToolNameRule(id="deny-http", description="No http", tool_name="http_request", action=PolicyAction.DENY)
    engine = PolicyEngine(rules=[rule])
    gateway = AgentGuardGateway(mock_client_session, engine, security_context=context)
    
    # Register tools
    await gateway.server._request_handlers["tools/list"].handler(None, None)
    
    import mcp.types as types
    req = types.CallToolRequestParams(name="http_request", arguments={})
    res = await gateway.server._request_handlers["tools/call"].handler(None, req)
    
    # Intent allowed it, but Policy Engine denied it!
    assert res.is_error
    assert "AgentGuard denied execution" in res.content[0].text
    assert mock_client_session.call_tool.call_count == 0


async def test_gateway_preserves_backwards_compatibility(mock_client_session):
    engine = PolicyEngine(rules=[])
    gateway = AgentGuardGateway(mock_client_session, engine) # no security context
    
    # Register tools
    await gateway.server._request_handlers["tools/list"].handler(None, None)
    
    import mcp.types as types
    req = types.CallToolRequestParams(name="http_request", arguments={})
    res = await gateway.server._request_handlers["tools/call"].handler(None, req)
    
    assert not res.is_error
    assert mock_client_session.call_tool.call_count == 1


async def test_gateway_resource_enforcement_denies_sensitive_file(mock_client_session):
    # Setup intent that ALLOWS FILE_READ
    intent = TaskIntent(
        intent_id="test",
        description="test",
        allowed_capabilities=(Capability.FILE_READ,),
        forbidden_capabilities=()
    )
    context = SecurityContext(session_id="s1", agent_id="a1", active_intent=intent)
    
    engine = PolicyEngine(rules=[])
    gateway = AgentGuardGateway(mock_client_session, engine, security_context=context)
    
    # Register tools
    await gateway.server._request_handlers["tools/list"].handler(None, None)
    
    import mcp.types as types
    # Attempt to read a sensitive file
    req = types.CallToolRequestParams(name="read_file", arguments={"path": ".env"})
    res = await gateway.server._request_handlers["tools/call"].handler(None, req)
    
    # Should be denied by resource validation, upstream count should be 0
    assert res.is_error
    assert "Resource constraint violation" in res.content[0].text
    assert mock_client_session.call_tool.call_count == 0


async def test_gateway_resource_enforcement_allows_safe_file(mock_client_session):
    # Setup intent that ALLOWS FILE_READ
    intent = TaskIntent(
        intent_id="test",
        description="test",
        allowed_capabilities=(Capability.FILE_READ,),
        forbidden_capabilities=()
    )
    context = SecurityContext(session_id="s1", agent_id="a1", active_intent=intent)
    
    engine = PolicyEngine(rules=[])
    gateway = AgentGuardGateway(mock_client_session, engine, security_context=context)
    
    # Register tools
    await gateway.server._request_handlers["tools/list"].handler(None, None)
    
    import mcp.types as types
    req = types.CallToolRequestParams(name="read_file", arguments={"path": "safe.txt"})
    res = await gateway.server._request_handlers["tools/call"].handler(None, req)
    
    assert not res.is_error
    assert mock_client_session.call_tool.call_count == 1

