"""Evaluation Scorer for AgentGuard benchmarks."""

from typing import List, Dict, Any
from agentguard.evaluation.models import EvaluationScenario, EvaluationResult, EvaluationScore, ActualOutcome, ExpectedOutcome

class EvaluationScorer:
    """Calculates metrics based on scenario expectations and actual outcomes."""
    
    def score(self, scenarios: List[EvaluationScenario], results: List[EvaluationResult]) -> EvaluationScore:
        total = len(scenarios)
        blocked = 0
        detected = 0
        missed = 0
        safe = 0
        false_positives = 0
        errors = 0
        
        attack_count = 0
        safe_count = 0
        
        exec_times = []
        policy_times = []
        analysis_times = []
        attack_risks = []
        safe_risks = []
        
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        category_breakdown = {}
        
        scenario_map = {s.scenario_id: s for s in scenarios}
        
        for result in results:
            scenario = scenario_map.get(result.scenario_id)
            if not scenario: continue
            
            exec_times.append(result.execution_time_ms)
            policy_times.append(result.policy_time_ms)
            analysis_times.append(result.analysis_time_ms)
            
            cat = scenario.category
            if cat not in category_breakdown:
                category_breakdown[cat] = {"total": 0, "blocked": 0, "detected": 0, "missed": 0, "false_positives": 0, "safe": 0}
            
            category_breakdown[cat]["total"] += 1
            
            if scenario.expected_outcome in (ExpectedOutcome.BLOCKED, ExpectedOutcome.DETECTED):
                attack_count += 1
                attack_risks.append(result.risk_score)
            else:
                safe_count += 1
                safe_risks.append(result.risk_score)
            
            if result.actual_outcome == ActualOutcome.BLOCKED:
                blocked += 1
                category_breakdown[cat]["blocked"] += 1
            elif result.actual_outcome == ActualOutcome.DETECTED:
                detected += 1
                category_breakdown[cat]["detected"] += 1
            elif result.actual_outcome == ActualOutcome.MISSED:
                missed += 1
                category_breakdown[cat]["missed"] += 1
            elif result.actual_outcome == ActualOutcome.SAFE:
                safe += 1
                category_breakdown[cat]["safe"] += 1
            elif result.actual_outcome == ActualOutcome.FALSE_POSITIVE:
                false_positives += 1
                category_breakdown[cat]["false_positives"] += 1
            else:
                errors += 1
                
            severity_breakdown[result.risk_severity] += 1
            
        detection_rate = 0.0
        if attack_count > 0:
            detection_rate = (blocked + detected) / attack_count
            
        fp_rate = 0.0
        if safe_count > 0:
            fp_rate = false_positives / safe_count
            
        miss_rate = 0.0
        if attack_count > 0:
            miss_rate = missed / attack_count
            
        error_rate = 0.0
        if total > 0:
            error_rate = errors / total
            
        return EvaluationScore(
            total=total,
            blocked=blocked,
            detected=detected,
            missed=missed,
            safe=safe,
            false_positives=false_positives,
            errors=errors,
            detection_rate=detection_rate,
            false_positive_rate=fp_rate,
            miss_rate=miss_rate,
            error_rate=error_rate,
            avg_execution_time_ms=sum(exec_times) / total if total else 0.0,
            avg_policy_time_ms=sum(policy_times) / total if total else 0.0,
            avg_analysis_time_ms=sum(analysis_times) / total if total else 0.0,
            avg_attack_risk=sum(attack_risks) / len(attack_risks) if attack_risks else 0.0,
            avg_safe_risk=sum(safe_risks) / len(safe_risks) if safe_risks else 0.0,
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown
        )
