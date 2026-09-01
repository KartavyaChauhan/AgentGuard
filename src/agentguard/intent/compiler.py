from typing import Iterable, Set, Tuple
import hashlib

from agentguard.outcome.models import TaskContract
from agentguard.intent.models import TaskIntent, IntentConstraint
from agentguard.intent.capabilities import Capability


# Deterministic mapping from known outcome evidence names to Capabilities
EVIDENCE_TO_CAPABILITY = {
    "tests_executed": Capability.TEST_EXECUTION,
    "tests_passed": Capability.TEST_EXECUTION,
    "file_modified": Capability.FILE_WRITE,
    "deployment_succeeded": Capability.NETWORK,
}


def _hash_id(contract_id: str) -> str:
    """Generate a deterministic intent ID from a contract ID."""
    return "intent-" + hashlib.sha256(contract_id.encode("utf-8")).hexdigest()[:16]


def compile_task_contract(contract: TaskContract) -> TaskIntent:
    """Deterministic compiler that converts a TaskContract into a TaskIntent."""
    
    # 1. Gather all required and optional evidence
    # Ensure they are immutable copies/references from the contract
    req_outcomes = tuple(str(x) for x in (contract.required_evidence or ()))
    opt_outcomes = tuple(str(x) for x in (contract.optional_evidence or ()))
    
    all_evidence = set(req_outcomes) | set(opt_outcomes)
    
    # 2. Map evidence to capabilities
    allowed_caps: Set[Capability] = set()
    for ev in all_evidence:
        if ev in EVIDENCE_TO_CAPABILITY:
            allowed_caps.add(EVIDENCE_TO_CAPABILITY[ev])
            
    # Convert to sorted list for deterministic order, then to tuple
    allowed_tuple = tuple(sorted(list(allowed_caps), key=lambda c: c.value))
    
    # 3. Default security boundaries (forbidden capabilities)
    forbidden_caps: Set[Capability] = set()
    constraints: list[IntentConstraint] = []
    
    if Capability.NETWORK not in allowed_caps:
        forbidden_caps.add(Capability.NETWORK)
        constraints.append(
            IntentConstraint(
                capability=Capability.NETWORK,
                allowed=False,
                reason="Network access is outside the inferred scope of this task."
            )
        )
        
    if Capability.PRIVILEGED not in allowed_caps:
        forbidden_caps.add(Capability.PRIVILEGED)
        constraints.append(
            IntentConstraint(
                capability=Capability.PRIVILEGED,
                allowed=False,
                reason="Privileged operations are outside the inferred scope of this task."
            )
        )
        
    # Ensure no overlap
    forbidden_caps = forbidden_caps - allowed_caps
    
    forbidden_tuple = tuple(sorted(list(forbidden_caps), key=lambda c: c.value))
    constraints_tuple = tuple(sorted(constraints, key=lambda c: c.capability.value))
    
    # 4. Generate deterministic description and intent ID
    intent_id = _hash_id(contract.contract_id)
    description = f"Intent compiled from TaskContract(contract_id='{contract.contract_id}')"
    if req_outcomes:
        description += f" requiring: {', '.join(sorted(req_outcomes))}"
    else:
        description += " requiring no specific outcomes"
        
    return TaskIntent(
        intent_id=intent_id,
        description=description,
        allowed_capabilities=allowed_tuple,
        forbidden_capabilities=forbidden_tuple,
        required_outcomes=req_outcomes,
        optional_outcomes=opt_outcomes,
        constraints=constraints_tuple
    )
