"""Loads attack scenarios from benchmark datasets."""

import json
import os
from typing import List

from agentguard.redteam.models import AttackScenario, AttackCall

def load_v1_scenarios() -> List[AttackScenario]:
    """Loads the v1 attacks.json dataset."""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
        "benchmarks",
        "redteam",
        "v1",
        "attacks.json"
    )
    
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    scenarios = []
    for item in data:
        calls = tuple(
            AttackCall(
                tool_name=c["tool_name"],
                arguments=c["arguments"]
            ) for c in item["trajectory"]
        )
        scenarios.append(
            AttackScenario(
                attack_id=item["attack_id"],
                name=item["name"],
                description=item["description"],
                severity=item["severity"],
                trajectory=calls,
                expected_security_property=item["expected_security_property"],
                category=item["category"],
            )
        )
        
    return scenarios
