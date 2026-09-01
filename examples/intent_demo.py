import asyncio

from agentguard.policy.engine import PolicyEngine
from agentguard.outcome.models import TaskContract
from agentguard.intent.compiler import compile_task_contract
from agentguard.context.models import SecurityContext
from agentguard.gateway.proxy import AgentGuardGateway

import mcp.types as types
from unittest.mock import AsyncMock

from agentguard.intent.models import ResourceConstraint, TaskIntent
from agentguard.intent.capabilities import Capability

async def main():
    # 1. Define a TaskContract
    contract = TaskContract(
        contract_id="task-123",
        task_name="Run test suite and fetch data",
        required_evidence=("tests_executed", "deployment_succeeded")
    )
    
    print(f"--- Task Contract ---")
    print(f"Required Evidence: {contract.required_evidence}\n")

    # 2. Compile to TaskIntent
    intent = compile_task_contract(contract)
    
    # Manually add a resource constraint to simulate a fully formed intent
    # allowing only api.github.com
    intent = TaskIntent(
        intent_id=intent.intent_id,
        description=intent.description,
        allowed_capabilities=(Capability.TEST_EXECUTION, Capability.FILE_READ, Capability.NETWORK),
        forbidden_capabilities=(Capability.PRIVILEGED,),
        required_outcomes=intent.required_outcomes,
        optional_outcomes=intent.optional_outcomes,
        constraints=intent.constraints,
        resource_constraints=(
            ResourceConstraint(Capability.NETWORK, ("api.github.com",)),
        )
    )
    print(f"--- Compiled TaskIntent ---")
    print(f"Intent ID: {intent.intent_id}")
    print(f"Description: {intent.description}")
    print(f"Allowed Capabilities: {[c.value for c in intent.allowed_capabilities]}")
    print(f"Forbidden Capabilities: {[c.value for c in intent.forbidden_capabilities]}\n")

    # 3. Create SecurityContext
    context = SecurityContext(
        session_id="demo-session",
        agent_id="demo-agent",
        task_contract=contract,
        active_intent=intent
    )

    # 4. Setup Mock Client Session (acting as the downstream MCP server we proxy to)
    mock_client = AsyncMock()
    class MockCallResult:
        content = [types.TextContent(type="text", text="Success from upstream server!")]
        is_error = False
    mock_client.call_tool.return_value = MockCallResult()
    
    # 5. Initialize Gateway with an EMPTY PolicyEngine
    # The policy engine by default allows everything (default allow).
    engine = PolicyEngine(rules=[])
    gateway = AgentGuardGateway(client_session=mock_client, policy_engine=engine, security_context=context)
    
    call_handler = gateway.server._request_handlers["tools/call"].handler
    
    # 6. Attempt a permitted tool with safe arguments
    print(f"--- Executing 'pytest' ---")
    req_allowed = types.CallToolRequestParams(name="pytest", arguments={})
    res_allowed = await call_handler(None, req_allowed)
    if res_allowed.is_error:
        print(f"[DENIED]: {res_allowed.content[0].text}")
    else:
        print(f"[ALLOWED]: {res_allowed.content[0].text}")
        
    print("\n")
    
    # 7. Attempt safe file read
    print(f"--- Executing 'read_file' (safe) ---")
    req_safe_file = types.CallToolRequestParams(name="read_file", arguments={"path": "safe_log.txt"})
    res_safe_file = await call_handler(None, req_safe_file)
    if res_safe_file.is_error:
        print(f"[DENIED]: {res_safe_file.content[0].text}")
    else:
        print(f"[ALLOWED]: {res_safe_file.content[0].text}")
        
    print("\n")
    
    # 8. Attempt sensitive file read
    print(f"--- Executing 'read_file' (.env) ---")
    req_bad_file = types.CallToolRequestParams(name="read_file", arguments={"path": ".env"})
    res_bad_file = await call_handler(None, req_bad_file)
    if res_bad_file.is_error:
        print(f"[DENIED]: {res_bad_file.content[0].text}")
    else:
        print(f"[ALLOWED]: {res_bad_file.content[0].text}")
        
    print("\n")
    
    # 9. Attempt safe network
    print(f"--- Executing 'http_request' (api.github.com) ---")
    req_safe_net = types.CallToolRequestParams(name="http_request", arguments={"url": "https://api.github.com/status"})
    res_safe_net = await call_handler(None, req_safe_net)
    if res_safe_net.is_error:
        print(f"[DENIED]: {res_safe_net.content[0].text}")
    else:
        print(f"[ALLOWED]: {res_safe_net.content[0].text}")
        
    print("\n")
    
    # 10. Attempt internal metadata network
    print(f"--- Executing 'http_request' (169.254.169.254) ---")
    req_bad_net = types.CallToolRequestParams(name="http_request", arguments={"url": "http://169.254.169.254/latest/meta-data/"})
    res_bad_net = await call_handler(None, req_bad_net)
    if res_bad_net.is_error:
        print(f"[DENIED]: {res_bad_net.content[0].text}")
    else:
        print(f"[ALLOWED]: {res_bad_net.content[0].text}")
        
    print(f"\nUpstream server was called {mock_client.call_tool.call_count} times (only the safe calls).")


if __name__ == "__main__":
    asyncio.run(main())
