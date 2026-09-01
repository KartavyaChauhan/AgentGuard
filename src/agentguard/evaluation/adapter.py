"""Adapter interfaces for consuming external benchmarks."""

from typing import Protocol, List, Dict, Any
import json
import os

from agentguard.evaluation.models import EvaluationScenario, ExpectedOutcome, EvaluationCall


class BenchmarkAdapter(Protocol):
    """Protocol for a benchmark adapter."""
    
    def load_scenarios(self) -> List[EvaluationScenario]:
        """Load and return evaluation scenarios."""
        ...
        
    def normalize_scenario(self, raw_data: Any) -> EvaluationScenario:
        """Normalize raw data into an EvaluationScenario."""
        ...
        
    def validate_scenario(self, scenario: EvaluationScenario) -> bool:
        """Validate a normalized scenario."""
        ...


class SyntheticBenchmarkAdapter:
    """Adapter for internal synthetic JSON scenarios."""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        
    def load_scenarios(self) -> List[EvaluationScenario]:
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Scenario file not found: {self.filepath}")
            
        with open(self.filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        scenarios = []
        for raw in data.get("scenarios", []):
            scenario = self.normalize_scenario(raw)
            if self.validate_scenario(scenario):
                scenarios.append(scenario)
        return scenarios
        
    def normalize_scenario(self, raw: dict[str, Any]) -> EvaluationScenario:
        trajectory = []
        for call_data in raw.get("trajectory", []):
            trajectory.append(
                EvaluationCall(
                    tool_name=call_data.get("tool_name", ""),
                    arguments=call_data.get("arguments", {})
                )
            )
            
        return EvaluationScenario(
            scenario_id=raw.get("scenario_id", ""),
            name=raw.get("name", ""),
            description=raw.get("description", ""),
            category=raw.get("category", "general"),
            technique=raw.get("technique", "none"),
            expected_outcome=ExpectedOutcome(raw.get("expected_outcome", "SAFE").upper()),
            trajectory=tuple(trajectory),
            task_contract=raw.get("task_contract"),
            metadata=raw.get("metadata", {})
        )
        
    def validate_scenario(self, scenario: EvaluationScenario) -> bool:
        if not scenario.scenario_id or not scenario.trajectory:
            return False
        return True
