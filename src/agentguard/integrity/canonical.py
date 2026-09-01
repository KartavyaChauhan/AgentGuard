import hashlib
import json
from mcp.types import Tool


def canonicalize_schema(schema: dict | None) -> dict:
    """Recursively sort and normalize a JSON schema."""
    if not isinstance(schema, dict):
        return schema
        
    normalized = {}
    for k in sorted(schema.keys()):
        v = schema[k]
        if isinstance(v, dict):
            normalized[k] = canonicalize_schema(v)
        elif isinstance(v, list):
            # We don't typically sort lists in schemas unless they are sets,
            # but we recursively canonicalize any objects inside them.
            normalized[k] = [canonicalize_schema(i) if isinstance(i, dict) else i for i in v]
        else:
            normalized[k] = v
            
    return normalized


def canonicalize_tool(tool: Tool) -> dict:
    """Convert an MCP Tool into a deterministic canonical dictionary."""
    canonical = {
        "name": tool.name,
        "description": tool.description or "",
        "input_schema": canonicalize_schema(tool.inputSchema if hasattr(tool, "inputSchema") else tool.input_schema)
    }
    
    # Optional fields that affect semantics
    if getattr(tool, "outputSchema", None) or getattr(tool, "output_schema", None):
        out_schema = getattr(tool, "outputSchema", getattr(tool, "output_schema", None))
        canonical["output_schema"] = canonicalize_schema(out_schema)
        
    return canonical


def fingerprint_tool(tool: Tool) -> str:
    """Generate a deterministic SHA-256 fingerprint for an MCP Tool."""
    canonical_dict = canonicalize_tool(tool)
    canonical_json = json.dumps(canonical_dict, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
