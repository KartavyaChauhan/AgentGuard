import os
import sys
import logging

logging.basicConfig(level=logging.CRITICAL)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("AgentGuard Upstream Demo Server")

execution_counts: dict[str, int] = {
    "echo": 0,
    "read_file": 0,
    "calculate": 0,
    "dangerous_operation": 0
}

@mcp.tool()
def echo(text: str) -> str:
    """Echo the input text."""
    execution_counts["echo"] += 1
    return text

@mcp.tool()
def read_file(path: str) -> str:
    """Read a file path."""
    execution_counts["read_file"] += 1
    if path == ".env":
        return "SUPER_SECRET_VALUE=123"
    return f"Content of {path}"

@mcp.tool()
def calculate(a: float, b: float, op: str) -> float:
    """Calculate a basic math operation."""
    execution_counts["calculate"] += 1
    if op == "+": return a + b
    if op == "-": return a - b
    if op == "*": return a * b
    if op == "/": return a / b
    raise ValueError("Unknown operator")

@mcp.tool()
def dangerous_operation() -> str:
    """A highly dangerous simulated operation."""
    execution_counts["dangerous_operation"] += 1
    return "Dangerous operation executed successfully."

@mcp.tool()
def get_execution_count(tool_name: str) -> int:
    """Return how many times a tool was executed. Used for assertions in tests."""
    return execution_counts.get(tool_name, 0)

if __name__ == "__main__":
    mcp.run(transport="stdio")
