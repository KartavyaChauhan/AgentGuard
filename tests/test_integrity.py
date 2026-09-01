from mcp.types import Tool
from agentguard.integrity.canonical import canonicalize_tool, fingerprint_tool
from agentguard.integrity.registry import ToolRegistry
from agentguard.integrity.findings import IntegrityFindingType


def test_canonical_json_ordering():
    tool1 = Tool(
        name="calc",
        description="test",
        inputSchema={"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "number"}}}
    )
    
    # Same tool, different property order
    tool2 = Tool(
        name="calc",
        description="test",
        inputSchema={"type": "object", "properties": {"b": {"type": "number"}, "a": {"type": "string"}}}
    )
    
    fp1 = fingerprint_tool(tool1)
    fp2 = fingerprint_tool(tool2)
    
    assert fp1 == fp2


def test_canonical_schema_change_detected():
    tool1 = Tool(
        name="calc",
        description="test",
        inputSchema={"type": "object", "properties": {"a": {"type": "string"}}}
    )
    
    # Changed type
    tool2 = Tool(
        name="calc",
        description="test",
        inputSchema={"type": "object", "properties": {"a": {"type": "number"}}}
    )
    
    fp1 = fingerprint_tool(tool1)
    fp2 = fingerprint_tool(tool2)
    
    assert fp1 != fp2


def test_registry_unapproved_new_tool():
    registry = ToolRegistry()
    tool = Tool(name="calc", description="test", inputSchema={"type": "object"})
    
    findings = registry.register_tool(tool, "srv-1")
    
    assert len(findings) == 1
    assert findings[0].type == IntegrityFindingType.UNAPPROVED_NEW_TOOL
    
    # Should not trigger again if unchanged
    findings2 = registry.register_tool(tool, "srv-1")
    assert len(findings2) == 0


def test_registry_rug_pull():
    registry = ToolRegistry()
    tool = Tool(name="calc", description="v1", inputSchema={"type": "object"})
    
    # Register and pin
    registry.register_tool(tool, "srv-1")
    registry.pin_tool("srv-1", "calc")
    
    # Rug pull (change description)
    mutated_tool = Tool(name="calc", description="v2", inputSchema={"type": "object"})
    
    findings = registry.register_tool(mutated_tool, "srv-1")
    
    assert len(findings) == 2
    types = [f.type for f in findings]
    assert IntegrityFindingType.TOOL_DESCRIPTION_CHANGED in types
    assert IntegrityFindingType.TOOL_RUG_PULL in types
    
    
def test_registry_shadowing():
    registry = ToolRegistry()
    tool = Tool(name="calc", description="test", inputSchema={"type": "object"})
    
    registry.register_tool(tool, "srv-1")
    
    # Same tool name, different server
    findings = registry.register_tool(tool, "srv-2")
    
    types = [f.type for f in findings]
    assert IntegrityFindingType.TOOL_SHADOWING in types
    assert IntegrityFindingType.UNAPPROVED_NEW_TOOL in types


def test_verify_tool_rug_pull():
    registry = ToolRegistry()
    tool = Tool(name="calc", description="v1", inputSchema={"type": "object"})
    
    registry.register_tool(tool, "srv-1")
    registry.pin_tool("srv-1", "calc")
    
    # Incoming tool call has mutated definition
    mutated_tool = Tool(name="calc", description="v2", inputSchema={"type": "object"})
    
    findings = registry.verify_tool(mutated_tool, "srv-1")
    assert len(findings) == 1
    assert findings[0].type == IntegrityFindingType.TOOL_RUG_PULL
