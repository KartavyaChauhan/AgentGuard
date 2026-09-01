"""Evaluation Report generation."""

import json
from dataclasses import dataclass
from typing import List
from agentguard.evaluation.models import EvaluationScore, EvaluationResult, EvaluationScenario

@dataclass
class EvaluationReport:
    """Combines score and results for presentation."""
    scenarios: List[EvaluationScenario]
    results: List[EvaluationResult]
    score: EvaluationScore
    baseline_mode: bool = False
    
    def to_dict(self) -> dict:
        results_data = []
        for r in self.results:
            results_data.append({
                "scenario_id": r.scenario_id,
                "expected_outcome": r.expected_outcome.value,
                "actual_outcome": r.actual_outcome.value,
                "risk_score": r.risk_score,
                "risk_severity": r.risk_severity,
                "explanation": r.explanation,
                "execution_time_ms": round(r.execution_time_ms, 2)
            })
            
        return {
            "summary": {
                "total": self.score.total,
                "blocked": self.score.blocked,
                "detected": self.score.detected,
                "missed": self.score.missed,
                "safe": self.score.safe,
                "false_positives": self.score.false_positives,
                "errors": self.score.errors,
                "detection_rate_pct": round(self.score.detection_rate * 100, 1),
                "false_positive_rate_pct": round(self.score.false_positive_rate * 100, 1),
                "miss_rate_pct": round(self.score.miss_rate * 100, 1),
                "baseline_mode": self.baseline_mode
            },
            "risk": {
                "avg_attack_risk": round(self.score.avg_attack_risk, 1),
                "avg_safe_risk": round(self.score.avg_safe_risk, 1)
            },
            "categories": self.score.category_breakdown,
            "severity": self.score.severity_breakdown,
            "performance": {
                "avg_execution_time_ms": round(self.score.avg_execution_time_ms, 2),
                "avg_policy_time_ms": round(self.score.avg_policy_time_ms, 2),
                "avg_analysis_time_ms": round(self.score.avg_analysis_time_ms, 2)
            },
            "results": results_data
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)
