from typing import Optional

from agentguard.intent.models import TaskIntent
from agentguard.intent.capabilities import capability_for_tool, Capability
from agentguard.intent.resources import validate_file_read, validate_network
from agentguard.policy.models import ToolRequest, PolicyDecision, PolicyAction, RiskLevel


class IntentEnforcer:
    """Evaluates a ToolRequest against the active TaskIntent to enforce least privilege."""
    
    def __init__(self, intent: Optional[TaskIntent] = None):
        self.intent = intent

    def evaluate(self, request: ToolRequest) -> PolicyDecision | None:
        """Evaluate the tool request against the intent constraints.
        
        Returns:
            PolicyDecision with action DENY if the tool violates the intent.
            None if the tool is explicitly allowed by the intent or if no intent is active,
            indicating that execution should proceed to standard policy evaluation.
        """
        if not self.intent:
            return None
            
        capability = capability_for_tool(request.tool_name)
        
        if capability is None:
            return PolicyDecision(
                action=PolicyAction.DENY,
                reason=f"Tool '{request.tool_name}' maps to an unknown capability. Intent enforcement defaults to least-privilege block.",
                rule_id="intent-unknown-capability-block",
                risk_level=RiskLevel.CRITICAL
            )
            
        if capability not in self.intent.allowed_capabilities:
            return PolicyDecision(
                action=PolicyAction.DENY,
                reason=f"Capability '{capability.value}' is not authorized by the active TaskIntent.",
                rule_id="intent-unauthorized-capability-block",
                risk_level=RiskLevel.CRITICAL
            )
            
        # Optional Resource Enforcement
        # Extract constraints specific to this capability
        allowed_resources = ()
        for rc in self.intent.resource_constraints:
            if rc.capability == capability:
                allowed_resources = rc.allowed_resources
                break
                
        if capability == Capability.FILE_READ or capability == Capability.FILE_WRITE:
            # Check all possible path arguments
            path_keys = {"path", "filename", "file", "filepath", "dir", "directory"}
            lower_args = {k.lower(): v for k, v in request.arguments.items()}
            
            found_arg = False
            for key in path_keys:
                if key in lower_args:
                    found_arg = True
                    arg_val = lower_args[key]
                    if not isinstance(arg_val, str):
                        return PolicyDecision(
                            action=PolicyAction.DENY,
                            reason=f"Resource constraint violation: Argument '{key}' must be a string.",
                            rule_id="intent-resource-file-block",
                            risk_level=RiskLevel.CRITICAL
                        )
                    
                    is_allowed, reason = validate_file_read(arg_val, allowed_resources)
                    if not is_allowed:
                        return PolicyDecision(
                            action=PolicyAction.DENY,
                            reason=f"Resource constraint violation: {reason}",
                            rule_id="intent-resource-file-block",
                            risk_level=RiskLevel.CRITICAL
                        )
                    elif allowed_resources:
                        # Explicitly allowed by intent constraints
                        return PolicyDecision(
                            action=PolicyAction.ALLOW,
                            reason="Explicitly authorized by TaskIntent resource constraints.",
                            rule_id="intent-explicit-allow",
                            risk_level=RiskLevel.LOW
                        )
                        
            if not found_arg:
                return PolicyDecision(
                    action=PolicyAction.DENY,
                    reason="Resource constraint violation: Missing expected target path argument.",
                    rule_id="intent-resource-file-block",
                    risk_level=RiskLevel.CRITICAL
                )
                            
        elif capability == Capability.NETWORK:
            # Check all possible network arguments
            url_keys = {"url", "endpoint", "uri", "host"}
            lower_args = {k.lower(): v for k, v in request.arguments.items()}
            
            found_arg = False
            for key in url_keys:
                if key in lower_args:
                    found_arg = True
                    arg_val = lower_args[key]
                    if not isinstance(arg_val, str):
                        return PolicyDecision(
                            action=PolicyAction.DENY,
                            reason=f"Resource constraint violation: Argument '{key}' must be a string.",
                            rule_id="intent-resource-network-block",
                            risk_level=RiskLevel.CRITICAL
                        )
                        
                    is_allowed, reason = validate_network(arg_val, allowed_resources)
                    if not is_allowed:
                        return PolicyDecision(
                            action=PolicyAction.DENY,
                            reason=f"Resource constraint violation: {reason}",
                            rule_id="intent-resource-network-block",
                            risk_level=RiskLevel.CRITICAL
                        )
            
            if not found_arg:
                return PolicyDecision(
                    action=PolicyAction.DENY,
                    reason="Resource constraint violation: Missing expected target network argument.",
                    rule_id="intent-resource-network-block",
                    risk_level=RiskLevel.CRITICAL
                )
                            
        # The capability (and resources, if any) is explicitly allowed.
        # Fall back to normal PolicyEngine evaluation.
        return None
