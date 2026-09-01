import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from mcp.types import Tool

from agentguard.integrity.canonical import fingerprint_tool
from agentguard.integrity.findings import (
    IntegrityFinding,
    IntegrityFindingType,
    create_integrity_finding,
)
from agentguard.intent.capabilities import capability_for_tool, Capability

logger = logging.getLogger(__name__)

@dataclass
class RegisteredTool:
    tool_name: str
    server_id: str
    fingerprint: str
    first_seen: datetime
    last_seen: datetime
    pinned: bool
    capability: Optional[Capability]
    canonical_definition: dict


class ToolRegistry:
    """Manages MCP tool definitions, tracks their integrity, and detects rug-pulls."""
    
    def __init__(self):
        # Maps (server_id, tool_name) -> RegisteredTool
        self._tools: dict[tuple[str, str], RegisteredTool] = {}
        # Used for shadow detection
        self._tool_names_to_servers: dict[str, set[str]] = {}
        
    def register_tool(self, tool: Tool, server_id: str) -> list[IntegrityFinding]:
        """Register a tool and check for integrity issues against known state."""
        findings = []
        tool_name = tool.name
        fingerprint = fingerprint_tool(tool)
        now = datetime.now(timezone.utc)
        
        # 1. Shadowing Check
        if tool_name in self._tool_names_to_servers:
            known_servers = self._tool_names_to_servers[tool_name]
            if server_id not in known_servers:
                findings.append(create_integrity_finding(
                    IntegrityFindingType.TOOL_SHADOWING,
                    tool_name,
                    server_id,
                    fingerprint,
                    {"known_servers": list(known_servers)}
                ))
        
        key = (server_id, tool_name)
        if key not in self._tools:
            # New tool
            from agentguard.integrity.canonical import canonicalize_tool
            self._tools[key] = RegisteredTool(
                tool_name=tool_name,
                server_id=server_id,
                fingerprint=fingerprint,
                first_seen=now,
                last_seen=now,
                pinned=False,  # Needs explicit pinning/approval
                capability=capability_for_tool(tool_name),
                canonical_definition=canonicalize_tool(tool)
            )
            
            if tool_name not in self._tool_names_to_servers:
                self._tool_names_to_servers[tool_name] = set()
            self._tool_names_to_servers[tool_name].add(server_id)
            
            findings.append(create_integrity_finding(
                IntegrityFindingType.UNAPPROVED_NEW_TOOL,
                tool_name,
                server_id,
                fingerprint,
                {"message": "Tool has been discovered but is not yet approved/pinned."}
            ))
        else:
            # Existing tool
            registered = self._tools[key]
            registered.last_seen = now
            
            if registered.fingerprint != fingerprint:
                # The definition changed
                from agentguard.integrity.canonical import canonicalize_tool
                new_canonical = canonicalize_tool(tool)
                
                # Determine what changed
                if new_canonical.get("description") != registered.canonical_definition.get("description"):
                    findings.append(create_integrity_finding(
                        IntegrityFindingType.TOOL_DESCRIPTION_CHANGED,
                        tool_name,
                        server_id,
                        fingerprint,
                        {"old": registered.canonical_definition.get("description"), "new": new_canonical.get("description")}
                    ))
                    
                if new_canonical.get("input_schema") != registered.canonical_definition.get("input_schema"):
                    findings.append(create_integrity_finding(
                        IntegrityFindingType.TOOL_SCHEMA_CHANGED,
                        tool_name,
                        server_id,
                        fingerprint,
                        {"old": registered.canonical_definition.get("input_schema"), "new": new_canonical.get("input_schema")}
                    ))
                    
                if new_canonical.get("output_schema") != registered.canonical_definition.get("output_schema"):
                    findings.append(create_integrity_finding(
                        IntegrityFindingType.TOOL_OUTPUT_SCHEMA_CHANGED,
                        tool_name,
                        server_id,
                        fingerprint,
                        {"old": registered.canonical_definition.get("output_schema"), "new": new_canonical.get("output_schema")}
                    ))
                    
                if registered.pinned:
                    # If pinned, this is a rug-pull violation
                    findings.append(create_integrity_finding(
                        IntegrityFindingType.TOOL_RUG_PULL,
                        tool_name,
                        server_id,
                        fingerprint,
                        {"message": "A pinned tool definition was changed. Execution will be blocked.", "expected_fingerprint": registered.fingerprint}
                    ))
                else:
                    # Unpinned tools can be updated dynamically
                    registered.fingerprint = fingerprint
                    registered.canonical_definition = new_canonical
                    
        return findings
        
    def pin_tool(self, server_id: str, tool_name: str) -> bool:
        """Explicitly approve and pin a tool definition to its current fingerprint."""
        key = (server_id, tool_name)
        if key in self._tools:
            self._tools[key].pinned = True
            return True
        return False
        
    def unpin_tool(self, server_id: str, tool_name: str) -> bool:
        """Unpin a tool, allowing it to be dynamically updated upon next discovery."""
        key = (server_id, tool_name)
        if key in self._tools:
            self._tools[key].pinned = False
            return True
        return False
        
    def verify_tool(self, tool: Tool, server_id: str) -> list[IntegrityFinding]:
        """Verify an incoming tool execution against the registry."""
        key = (server_id, tool.name)
        if key not in self._tools:
            fingerprint = fingerprint_tool(tool)
            return [create_integrity_finding(
                IntegrityFindingType.UNAPPROVED_NEW_TOOL,
                tool.name,
                server_id,
                fingerprint,
                {"message": "Tool execution attempted before discovery/approval."}
            )]
            
        registered = self._tools[key]
        fingerprint = fingerprint_tool(tool)
        
        if registered.pinned and registered.fingerprint != fingerprint:
            return [create_integrity_finding(
                IntegrityFindingType.TOOL_RUG_PULL,
                tool.name,
                server_id,
                fingerprint,
                {"expected_fingerprint": registered.fingerprint, "message": "Tool definition changed at execution time."}
            )]
            
        return []
        
    def get_registered_tools(self) -> list[RegisteredTool]:
        return list(self._tools.values())
        
    def get_tool(self, server_id: str, tool_name: str) -> Optional[RegisteredTool]:
        return self._tools.get((server_id, tool_name))
