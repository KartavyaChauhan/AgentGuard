import sys
from mcp.server.mcpserver import MCPServer

from agentguard.policy.engine import PolicyEngine
from agentguard.execution.executor import ToolExecutor
from agentguard.mcp.adapter import MCPAdapter


def create_demo_server(engine: PolicyEngine, executor: ToolExecutor) -> MCPServer:
    """Creates a demo MCP server with tools routed through AgentGuard."""
    
    server = MCPServer("AgentGuard Demo Server")
    adapter = MCPAdapter(executor)

    # Define some demo tools
    def list_files(directory: str) -> str:
        """Lists files in a directory."""
        import os
        try:
            return "\n".join(os.listdir(directory))
        except Exception as e:
            return f"Error listing files: {e}"

    def read_file(path: str) -> str:
        """Reads the content of a file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {e}"

    def calculate(a: float, b: float, operator: str) -> float:
        """Calculates a mathematical expression."""
        if operator == "+":
            return a + b
        elif operator == "-":
            return a - b
        elif operator == "*":
            return a * b
        elif operator == "/":
            return a / b
        raise ValueError(f"Unknown operator: {operator}")

    def git_push_force() -> str:
        """Simulates a force push."""
        return "Pushed to remote (force)."

    # Register tools with executor so they can be looked up when allowed
    executor.register_tool("list_files", list_files)
    executor.register_tool("read_file", read_file)
    executor.register_tool("calculate", calculate)
    executor.register_tool("git_push_force", git_push_force)

    # Add wrapped tools to MCP server
    server.add_tool(adapter.wrap_tool(list_files))
    server.add_tool(adapter.wrap_tool(read_file))
    server.add_tool(adapter.wrap_tool(calculate))
    server.add_tool(adapter.wrap_tool(git_push_force))

    return server


if __name__ == "__main__":
    import asyncio
    from agentguard.policy.defaults import create_default_engine
    
    engine = create_default_engine()
    executor = ToolExecutor(policy_engine=engine)
    server = create_demo_server(engine, executor)
    
    # Run server on stdio
    asyncio.run(server.run_stdio_async())
