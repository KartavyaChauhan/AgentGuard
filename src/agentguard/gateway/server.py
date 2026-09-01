import asyncio
import logging
from typing import Optional

from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from mcp.server.stdio import stdio_server

from agentguard.policy.engine import PolicyEngine
from agentguard.events.store import EventStore
from .models import GatewayConfig
from .proxy import AgentGuardGateway

logger = logging.getLogger(__name__)

async def run_gateway(config: GatewayConfig, policy_engine: PolicyEngine, event_store: Optional[EventStore] = None):
    """Run the AgentGuard Gateway.
    
    This function spawns the upstream MCP server, connects to it,
    and then starts the gateway MCP server on stdio.
    """
    server_parameters = StdioServerParameters(
        command=config.upstream_command,
        args=config.upstream_args,
    )
    
    try:
        async with stdio_client(server_parameters) as (read, write):
            async with ClientSession(read, write) as client_session:
                await client_session.initialize()
                
                gateway = AgentGuardGateway(
                    client_session=client_session,
                    policy_engine=policy_engine,
                    event_store=event_store
                )
                
                async with stdio_server() as (server_read, server_write):
                    await gateway.server.run(
                        server_read,
                        server_write,
                        gateway.server.create_initialization_options()
                    )
    except Exception as e:
        logger.error(f"Gateway failed: {e}")
        raise
