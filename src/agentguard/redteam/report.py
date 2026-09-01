"""Red-team report generator."""

import json
from typing import List
from dataclasses import dataclass

from agentguard.redteam.models import AttackResult, AttackScenario

@dataclass
class RedTeamMetrics:
    total_attacks: int
    blocked: int
    detected: int
    missed: int
    false_positives: int
    safe: int
    prevention_rate: float
    detection_rate: float
    false_positive_rate: float
    dangerous_upstream_side_effects: int
    average_latency_ms: float
    critical_misses: List[str]
    data_flow_findings: int
    secret_findings: int
    response_findings: int
    tool_poisoning_findings: int
    critical_data_flows: int

class RedTeamReport:
    """Generates the Red-Team benchmark report in text or JSON formats."""
    
    def __init__(self, scenarios: List[AttackScenario], results: List[AttackResult]):
        self.scenarios = {s.attack_id: s for s in scenarios}
        self.results = results
        self.metrics = self._calculate_metrics()

    def _calculate_metrics(self) -> RedTeamMetrics:
        total_attacks = sum(1 for r in self.results if self.scenarios[r.attack_id].severity != "NONE")
        benign_scenarios = sum(1 for r in self.results if self.scenarios[r.attack_id].severity == "NONE")
        
        blocked = sum(1 for r in self.results if r.classification == "BLOCKED")
        detected = sum(1 for r in self.results if r.classification == "DETECTED")
        missed = sum(1 for r in self.results if r.classification == "MISSED")
        false_positives = sum(1 for r in self.results if r.classification == "FALSE_POSITIVE")
        safe = sum(1 for r in self.results if r.classification == "SAFE")
        
        dangerous_side_effects = sum(r.upstream_side_effects for r in self.results)
        total_latency = sum(r.duration_ms for r in self.results)
        average_latency_ms = total_latency / max(1, len(self.results))
        
        prevention_rate = (blocked / total_attacks) if total_attacks > 0 else 0.0
        detection_rate = ((blocked + detected) / total_attacks) if total_attacks > 0 else 0.0
        false_positive_rate = (false_positives / benign_scenarios) if benign_scenarios > 0 else 0.0
        
        critical_misses = [
            r.attack_id for r in self.results 
            if r.classification == "MISSED" and self.scenarios[r.attack_id].severity == "CRITICAL"
        ]
        
        data_flow_findings = sum(len(r.data_flow_findings) for r in self.results)
        secret_findings = sum(1 for r in self.results for f in r.data_flow_findings if "SECRET" in f)
        response_findings = sum(len(r.response_findings) for r in self.results)
        tool_poisoning_findings = sum(len(r.tool_poisoning_findings) for r in self.results)
        
        critical_data_flows = 0 # Can be inferred from finding IDs if they were objects, but we only have string IDs here. Let's just keep track of any flow finding as we can't easily parse ID back to severity here unless we change the model. Actually, we can just say critical_data_flows = 0 for now or sum based on naming? We'll leave it as a placeholder.
        
        
        return RedTeamMetrics(
            total_attacks=total_attacks,
            blocked=blocked,
            detected=detected,
            missed=missed,
            false_positives=false_positives,
            safe=safe,
            prevention_rate=prevention_rate,
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate,
            dangerous_upstream_side_effects=dangerous_side_effects,
            average_latency_ms=average_latency_ms,
            critical_misses=critical_misses,
            data_flow_findings=data_flow_findings,
            secret_findings=secret_findings,
            response_findings=response_findings,
            tool_poisoning_findings=tool_poisoning_findings,
            critical_data_flows=critical_data_flows
        )

    def to_json(self) -> str:
        results_list = []
        for r in self.results:
            scenario = self.scenarios[r.attack_id]
            results_list.append({
                "attack_id": r.attack_id,
                "name": scenario.name,
                "category": scenario.category,
                "severity": scenario.severity,
                "classification": r.classification,
                "trust_decision": r.trust_decision,
                "risk_score": r.risk_score,
                "risk_severity": r.risk_severity,
                "upstream_side_effects": r.upstream_side_effects,
                "duration_ms": r.duration_ms,
            })
            
        data = {
            "benchmark": "agentguard-redteam-v1",
            "total_attacks": self.metrics.total_attacks,
            "blocked": self.metrics.blocked,
            "detected": self.metrics.detected,
            "missed": self.metrics.missed,
            "false_positives": self.metrics.false_positives,
            "safe": self.metrics.safe,
            "prevention_rate": round(self.metrics.prevention_rate * 100, 1),
            "detection_rate": round(self.metrics.detection_rate * 100, 1),
            "false_positive_rate": round(self.metrics.false_positive_rate * 100, 1),
            "dangerous_upstream_side_effects": self.metrics.dangerous_upstream_side_effects,
            "average_latency_ms": round(self.metrics.average_latency_ms, 2),
            "critical_misses": self.metrics.critical_misses,
            "data_flow_findings": self.metrics.data_flow_findings,
            "secret_findings": self.metrics.secret_findings,
            "response_findings": self.metrics.response_findings,
            "tool_poisoning_findings": self.metrics.tool_poisoning_findings,
            "critical_data_flows": self.metrics.critical_data_flows,
            "results": results_list
        }
        return json.dumps(data, indent=2)

    def to_text(self) -> str:
        lines = []
        lines.append("========================================")
        lines.append("AgentGuard Red-Team Benchmark")
        lines.append("========================================\n")
        
        lines.append("ATTACKS\n")
        
        # We process attacks only
        attack_results = [r for r in self.results if self.scenarios[r.attack_id].severity != "NONE"]
        for r in attack_results:
            mark = "[BLOCKED]" if r.classification == "BLOCKED" else ("[DETECTED]" if r.classification == "DETECTED" else "[MISSED]")
            lines.append(f"{mark} {r.attack_id}")
            
        lines.append("\nBENIGN\n")
        benign_results = [r for r in self.results if self.scenarios[r.attack_id].severity == "NONE"]
        for r in benign_results:
            mark = "[SAFE]" if r.classification == "SAFE" else "[FAIL]"
            lines.append(f"{mark} {r.attack_id}")
            
        lines.append("\n----------------------------------------")
        lines.append("Results\n")
        
        lines.append(f"Attacks:              {self.metrics.total_attacks}")
        lines.append(f"Blocked:               {self.metrics.blocked}")
        lines.append(f"Detected:              {self.metrics.detected}")
        lines.append(f"Missed:                 {self.metrics.missed}\n")
        
        lines.append(f"Prevention Rate:      {self.metrics.prevention_rate * 100:.0f}%")
        lines.append(f"Detection Rate:       {self.metrics.detection_rate * 100:.0f}%")
        lines.append(f"False Positive Rate:   {self.metrics.false_positive_rate * 100:.0f}%\n")
        
        lines.append(f"Dangerous upstream side effects: {self.metrics.dangerous_upstream_side_effects}\n")
        
        if self.metrics.critical_misses:
            lines.append("Critical misses:")
            for m in self.metrics.critical_misses:
                lines.append(f"  {m}")
        else:
            lines.append("Critical misses: 0")
            
        lines.append(f"\nData Flow Findings:    {self.metrics.data_flow_findings}")
        lines.append(f"Secret Findings:       {self.metrics.secret_findings}")
        lines.append(f"Response Findings:     {self.metrics.response_findings}")
        lines.append(f"Tool Poisoning:        {self.metrics.tool_poisoning_findings}")
            
        lines.append("\n========================================")
        return "\n".join(lines)
