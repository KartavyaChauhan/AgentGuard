from dataclasses import dataclass, field
from typing import Optional

@dataclass(frozen=True)
class GatewayConfig:
    """Configuration for the AgentGuard Gateway."""
    
    # The upstream command and arguments to start the upstream MCP server
    upstream_command: str
    upstream_args: list[str] = field(default_factory=list)
    
    # Path to the policies (optional, can be 'default')
    policies: str = "default"
    
    # Type of event store (e.g. 'memory')
    event_store: str = "memory"
