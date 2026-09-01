from dataclasses import dataclass, field
from typing import Any

from agentguard.intent.capabilities import Capability


@dataclass(frozen=True)
class IntentConstraint:
    """An immutable constraint on an agent's capability."""
    capability: Capability
    allowed: bool
    reason: str = ""
    
    def __post_init__(self):
        if not isinstance(self.reason, str):
            raise ValueError("reason must be a string")


@dataclass(frozen=True)
class ResourceConstraint:
    """An immutable constraint specifying allowed resources for a capability."""
    capability: Capability
    allowed_resources: tuple[str, ...]
    
    def __post_init__(self):
        object.__setattr__(self, "allowed_resources", tuple(self.allowed_resources))


@dataclass(frozen=True)
class TaskIntent:
    """An immutable representation of what an agent is authorized to do."""
    intent_id: str
    description: str
    allowed_capabilities: tuple[Capability, ...]
    forbidden_capabilities: tuple[Capability, ...]
    required_outcomes: tuple[str, ...] = field(default_factory=tuple)
    optional_outcomes: tuple[str, ...] = field(default_factory=tuple)
    constraints: tuple[IntentConstraint, ...] = field(default_factory=tuple)
    resource_constraints: tuple[ResourceConstraint, ...] = field(default_factory=tuple)
    
    def __post_init__(self):
        if not self.intent_id or not self.intent_id.strip():
            raise ValueError("intent_id cannot be empty")
        if not self.description or not self.description.strip():
            raise ValueError("description cannot be empty")
            
        allowed_set = set(self.allowed_capabilities)
        forbidden_set = set(self.forbidden_capabilities)
        
        if overlap := allowed_set.intersection(forbidden_set):
            raise ValueError(f"Capabilities cannot be both allowed and forbidden: {', '.join(c.value for c in overlap)}")
            
        # Ensure deep immutability by converting any iterable to a tuple, just in case
        object.__setattr__(self, "allowed_capabilities", tuple(self.allowed_capabilities))
        object.__setattr__(self, "forbidden_capabilities", tuple(self.forbidden_capabilities))
        object.__setattr__(self, "required_outcomes", tuple(self.required_outcomes))
        object.__setattr__(self, "optional_outcomes", tuple(self.optional_outcomes))
        object.__setattr__(self, "constraints", tuple(self.constraints))
        object.__setattr__(self, "resource_constraints", tuple(self.resource_constraints))

    def to_dict(self) -> dict[str, Any]:
        """Serialize deterministically."""
        return {
            "intent_id": self.intent_id,
            "description": self.description,
            "allowed_capabilities": sorted([c.value for c in self.allowed_capabilities]),
            "forbidden_capabilities": sorted([c.value for c in self.forbidden_capabilities]),
            "required_outcomes": sorted(list(self.required_outcomes)),
            "optional_outcomes": sorted(list(self.optional_outcomes)),
            "constraints": [
                {
                    "capability": c.capability.value,
                    "allowed": c.allowed,
                    "reason": c.reason
                }
                # Sort constraints by capability name for deterministic ordering
                for c in sorted(self.constraints, key=lambda x: x.capability.value)
            ],
            "resource_constraints": [
                {
                    "capability": rc.capability.value,
                    "allowed_resources": sorted(list(rc.allowed_resources))
                }
                for rc in sorted(self.resource_constraints, key=lambda x: x.capability.value)
            ]
        }
