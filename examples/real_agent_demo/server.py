import sys
import os
import tempfile
import asyncio
from mcp.server.mcpserver import MCPServer

DANGEROUS_CALL_COUNT = 0

def create_demo_server() -> MCPServer:
    """Creates the upstream Demo MCP server with 6 tools."""
    server = MCPServer("Demo Upstream Server", version="1.0.0")
    
    # Create temporary workspace for safety
    workspace_dir = tempfile.mkdtemp(prefix="agentguard_demo_")
    
    def _enforce_path(path: str) -> str:
        """Ensures path is inside workspace."""
        if ".." in path or path.startswith("/") or path.startswith("\\") or path.startswith("C:"):
            raise ValueError(f"Path {path} must be relative and cannot contain '..'")
        return os.path.join(workspace_dir, path)

    @server.tool(name="read_file", description="Reads a file from the workspace.")
    def read_file(path: str) -> str:
        safe_path = _enforce_path(path)
        if not os.path.exists(safe_path):
            return f"File not found: {path}"
        with open(safe_path, "r", encoding="utf-8") as f:
            return f.read()

    @server.tool(name="write_file", description="Writes content to a file in the workspace.")
    def write_file(path: str, content: str) -> str:
        safe_path = _enforce_path(path)
        with open(safe_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Successfully wrote to {path}"

    @server.tool(name="shell", description="Executes a safe shell command.")
    def shell(command: str) -> str:
        allowed = ["safe-demo-command", "echo", "date", "ls"]
        base_cmd = command.split()[0] if command else ""
        if base_cmd not in allowed:
            raise ValueError(f"Command '{base_cmd}' is not allowed. Safe commands only.")
        return f"Simulated execution of: {command}"

    @server.tool(name="http_request", description="Makes a simulated HTTP request.")
    def http_request(url: str) -> str:
        if not (url.startswith("https://example.com") or url.startswith("https://example.invalid")):
            raise ValueError(f"URL '{url}' is not allowed in demo.")
        return f"Simulated response from {url}"

    @server.tool(name="run_tests", description="Simulates running tests.")
    def run_tests(test_status: str) -> str:
        return f"Tests executed. Status: {test_status}"

    @server.tool(name="calculate", description="Calculates mathematical expressions.")
    def calculate(a: float, b: float) -> float:
        return a + b  # Simplified for demo

    @server.tool(name="dangerous_side_effect", description="A tool that has side effects.")
    def dangerous_side_effect() -> str:
        global DANGEROUS_CALL_COUNT
        DANGEROUS_CALL_COUNT += 1
        return "Executed!"

    return server

if __name__ == "__main__":
    server = create_demo_server()
    asyncio.run(server.run_stdio_async())
