"""Deterministic rules and heuristic values for trajectory risk scoring."""

from typing import Any

from agentguard.events.models import ToolEvent
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.models import ExecutionStatus
from agentguard.behavior.models import BehaviorFinding
from agentguard.risk.models import RiskContribution

def evaluate_event(event: ToolEvent) -> tuple[int, str]:
    """Determine the heuristic score and reason for a single event.
    
    Returns
    -------
    tuple[int, str]
        Points and explanation reason.
    """
    # Failed execution
    if event.execution_status == ExecutionStatus.FAILED:
        return 5, "Failed tool execution"
    
    # Approval required (regardless of execution outcome)
    if event.policy_action == PolicyAction.REQUIRE_APPROVAL:
        return 10, "Approval-required action"

    # Specific tool heuristics
    if event.tool_name == "read_file":
        path = str(event.arguments.get("path", ""))
        # Simple deterministic heuristic for sensitive paths
        if any(sensitive in path for sensitive in [".env", "secrets", "credentials", "id_rsa", "passwd"]):
            # Sanitize path in explanation to avoid raw secrets
            safe_path = path.split("/")[-1] if "/" in path else path
            return 30, f"Sensitive file access: {safe_path}"
        return 0, "Normal read_file"
        
    elif event.tool_name in ("http_request", "fetch", "curl"):
        return 10, "Network request"
        
    elif event.tool_name in ("shell", "bash", "cmd", "run_command"):
        return 15, "Shell execution"
        
    elif event.tool_name == "sudo" or event.tool_name.startswith("privileged_"):
        return 25, "Privileged operation"
        
    elif event.tool_name == "git_push_force" or (event.tool_name == "git_push" and event.arguments.get("force") is True):
        return 20, "Force git push"

    # Normal operations
    return 0, f"Normal {event.tool_name} operation"

def evaluate_finding(finding: BehaviorFinding) -> tuple[int, str]:
    """Determine the heuristic score and reason for a behavior finding."""
    if finding.severity == RiskLevel.CRITICAL:
        return 30, f"Critical behavioral finding: {finding.title}"
    elif finding.severity == RiskLevel.HIGH:
        return 20, f"High behavioral finding: {finding.title}"
    elif finding.severity == RiskLevel.MEDIUM:
        return 10, f"Medium behavioral finding: {finding.title}"
    elif finding.severity == RiskLevel.LOW:
        return 5, f"Low behavioral finding: {finding.title}"
    
    return 0, f"Unknown finding: {finding.title}"
