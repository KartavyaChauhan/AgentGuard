import json
import os
import shlex
from typing import Optional
from .models import GatewayConfig

VALID_EVENT_STORES = ("memory", "sqlite")

def load_config(
    path: Optional[str] = None,
    cli_upstream: Optional[str] = None,
    cli_policies: Optional[str] = None
) -> GatewayConfig:
    """Load configuration from a JSON file and/or CLI arguments."""
    policies = "default"
    event_store = "memory"
    upstream_cmd = None
    upstream_args = []
    
    if path:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Configuration file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            policies = data.get("policies", policies)
            event_store = data.get("event_store", event_store)
            if event_store not in VALID_EVENT_STORES:
                raise ValueError(
                    f"Unsupported event_store backend: '{event_store}'. "
                    f"Supported backends are: {', '.join(VALID_EVENT_STORES)}"
                )
            if "upstream" in data:
                # If it's a string, split it
                if isinstance(data["upstream"], str):
                    parts = shlex.split(data["upstream"], posix=(os.name != 'nt'))
                    if parts:
                        upstream_cmd = parts[0]
                        upstream_args = parts[1:]
                elif isinstance(data["upstream"], list):
                    if data["upstream"]:
                        upstream_cmd = data["upstream"][0]
                        upstream_args = data["upstream"][1:]

    # CLI upstream overrides config file
    if cli_upstream:
        parts = shlex.split(cli_upstream, posix=(os.name != 'nt'))
        if parts:
            upstream_cmd = parts[0]
            upstream_args = parts[1:]

    # CLI policies override config file
    if cli_policies:
        policies = cli_policies
            
    if not upstream_cmd:
        raise ValueError("Upstream command is required either in config or via --upstream flag.")
        
    return GatewayConfig(
        upstream_command=upstream_cmd,
        upstream_args=upstream_args,
        policies=policies,
        event_store=event_store
    )
