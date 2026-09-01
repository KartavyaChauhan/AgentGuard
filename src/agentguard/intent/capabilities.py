import enum
from typing import Iterable


class Capability(str, enum.Enum):
    """High-level capabilities of an agent."""
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    SHELL = "SHELL"
    NETWORK = "NETWORK"
    ENCODING = "ENCODING"
    PRIVILEGED = "PRIVILEGED"
    TEST_EXECUTION = "TEST_EXECUTION"
    GIT = "GIT"
    COMPUTATION = "COMPUTATION"


def capability_for_tool(tool_name: str) -> Capability | None:
    """Map a tool name to a Capability deterministically.
    
    Matching is case-insensitive, but requires exact or explicitly mapped known names.
    No fuzzy matching.
    """
    if not isinstance(tool_name, str):
        return None
        
    normalized = tool_name.strip().lower()
    
    mapping = {
        "read_file": Capability.FILE_READ,
        "list_files": Capability.FILE_READ,
        "write_file": Capability.FILE_WRITE,
        "edit_file": Capability.FILE_WRITE,
        "modify_file": Capability.FILE_WRITE,
        "shell": Capability.SHELL,
        "run_shell": Capability.SHELL,
        "http_request": Capability.NETWORK,
        "network_request": Capability.NETWORK,
        "base64_encode": Capability.ENCODING,
        "encode": Capability.ENCODING,
        "sudo": Capability.PRIVILEGED,
        "run_sudo": Capability.PRIVILEGED,
        "run_tests": Capability.TEST_EXECUTION,
        "pytest": Capability.TEST_EXECUTION,
        "git_push": Capability.GIT,
        "git_pull": Capability.GIT,
        "git_commit": Capability.GIT,
        "calculate": Capability.COMPUTATION,
        "failed_tool": Capability.TEST_EXECUTION,
        "poisoned_tool": Capability.TEST_EXECUTION,
    }
    
    return mapping.get(normalized, None)


def capabilities_for_tools(tool_names: Iterable[str]) -> dict[str, Capability | None]:
    """Map multiple tool names to Capabilities deterministically."""
    result = {}
    for name in tool_names:
        result[name] = capability_for_tool(name)
    return result
