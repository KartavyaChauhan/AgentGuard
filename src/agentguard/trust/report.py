"""Trust reporting and formatting."""

from __future__ import annotations
import json
from dataclasses import asdict

from agentguard.trust.models import TrustAssessment, TrustDecision


class TrustReport:
    """Formats a TrustAssessment for CLI output."""

    def __init__(self, assessment: TrustAssessment):
        self.assessment = assessment

    def to_text(self) -> str:
        """Render the trust assessment as a human-readable string."""
        a = self.assessment
        
        lines = [
            "AgentGuard Trust Assessment",
            "",
            f"Session: {a.session_id}",
            f"Agent: {a.agent_id}",
            f"Task: {a.task_contract_id or 'none'}",
            "",
            f"Decision: {a.decision.value}",
            "",
            "Security",
            f"  Policy: {a.policy_status}",
            f"  Behavior: {a.behavior_status}",
            f"  Invariants: {a.invariant_status}",
            f"  Risk: {a.risk_severity} ({a.risk_score})",
            "",
            "Outcome",
            f"  Status: {a.outcome_status}",
            "  Evidence:"
        ]
        
        if a.evidence:
            for k, v in a.evidence.items():
                mark = "✓" if v else "✗"
                lines.append(f"    {mark} {k}")
        else:
            lines.append("    (no evidence required or provided)")
            
        lines.append("")
        lines.append(f"Confidence: {a.confidence:.2f}")
        
        return "\n".join(lines)

    def to_json(self) -> str:
        """Render the trust assessment as JSON."""
        a = self.assessment
        data = {
            "decision": a.decision.value,
            "risk_score": a.risk_score,
            "risk_severity": a.risk_severity,
            "policy_status": a.policy_status,
            "behavior_status": a.behavior_status,
            "invariant_status": a.invariant_status,
            "outcome_status": a.outcome_status,
            "evidence": a.evidence,
            "reasons": list(a.reasons),
        }
        return json.dumps(data, indent=2)
