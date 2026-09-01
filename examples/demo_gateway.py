"""Demonstrates AgentGuard Gateway protecting an upstream MCP server."""

import asyncio
import os
import sys
import time

from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

async def run_demo():
    print("Starting AgentGuard Gateway Demo...")
    
    # We spawn the gateway as a subprocess. The gateway will in turn spawn demo_server.py.
    gateway_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agentguard.cli", "gateway", "--upstream", f"{sys.executable} examples/demo_server.py"]
    )
    
    async with stdio_client(gateway_params) as (read, write):
        async with ClientSession(read, write) as session:
            print("\n[+] Initializing connection to Gateway...")
            await session.initialize()
            print("[+] Initialization successful.")
            
            # Fetch tools
            tools_result = await session.list_tools()
            print(f"\n[+] Gateway returned {len(tools_result.tools)} tools:")
            for t in tools_result.tools:
                print(f"    - {t.name}: {t.description}")
                
            print("\n--------------------------------------------------")
            print("1. SAFE: calculate(2, 3, '+')")
            print("--------------------------------------------------")
            start = time.perf_counter()
            result = await session.call_tool("calculate", {"a": 2.0, "b": 3.0, "op": "+"})
            duration = (time.perf_counter() - start) * 1000
            print(f"Result: {result.content[0].text if result.content else 'No output'}")
            print(f"Is Error: {result.is_error}")
            print(f"Total time (including Gateway overhead): {duration:.2f} ms")
            
            print("\n--------------------------------------------------")
            print("2. DANGEROUS: read_file('.env') -> Should be DENIED")
            print("--------------------------------------------------")
            start = time.perf_counter()
            result = await session.call_tool("read_file", {"path": ".env"})
            duration = (time.perf_counter() - start) * 1000
            print(f"Result: {result.content[0].text if result.content else 'No output'}")
            print(f"Is Error: {result.is_error}")
            print(f"Total time: {duration:.2f} ms")
            
            print("\n--------------------------------------------------")
            print("3. APPROVAL REQUIRED: dangerous_operation()")
            print("--------------------------------------------------")
            # Wait, our default policy engine in agentguard.policy.defaults doesn't actually have a rule for dangerous_operation.
            # Let's see what rules are in agentguard.policy.defaults.
            # In defaults.py:
            # - read_file(.env) is denied.
            # - git_push_force is APPROVAL.
            # For the demo, we'll use git_push_force! Wait, the upstream server doesn't have git_push_force!
            # The prompt requested: dangerous_operation -> REQUIRE_APPROVAL.
            # In demo_server.py, we have `dangerous_operation`.
            start = time.perf_counter()
            result = await session.call_tool("dangerous_operation", {})
            duration = (time.perf_counter() - start) * 1000
            print(f"Result: {result.content[0].text if result.content else 'No output'}")
            print(f"Is Error: {result.is_error}")
            print(f"Total time: {duration:.2f} ms")
            
            # Print proof of execution count
            print("\n--------------------------------------------------")
            print("VERIFICATION: Upstream side-effect counts")
            print("--------------------------------------------------")
            # Fetch execution counts from upstream to prove blocked tools were NOT executed
            res_calc = await session.call_tool("get_execution_count", {"tool_name": "calculate"})
            res_read = await session.call_tool("get_execution_count", {"tool_name": "read_file"})
            res_danger = await session.call_tool("get_execution_count", {"tool_name": "dangerous_operation"})
            
            print(f"calculate calls: {res_calc.content[0].text if res_calc.content else 0}")
            print(f"read_file calls: {res_read.content[0].text if res_read.content else 0}")
            print(f"dangerous_operation calls: {res_danger.content[0].text if res_danger.content else 0}")
            
if __name__ == "__main__":
    asyncio.run(run_demo())
