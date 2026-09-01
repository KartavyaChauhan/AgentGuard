"""Deterministic unified trust decision engine."""

from __future__ import annotations
from typing import Iterable
import datetime
import traceback

from agentguard.events.models import ToolEvent
from agentguard.context.models import SecurityContext
from agentguard.policy.models import PolicyDecision, PolicyAction, RiskLevel
from agentguard.behavior.models import BehaviorFinding
from agentguard.invariants.models import InvariantViolation
from agentguard.outcome.models import OutcomeAssessment
from agentguard.risk.models import RiskAssessment
from agentguard.dataflow.models import DataFinding, ResponseFinding

from agentguard.trust.models import TrustAssessment, TrustDecision
from agentguard.trust.policy import TrustConfig, DEFAULT_TRUST_CONFIG


class TrustEngine:
    """Evaluates all existing security signals to produce a deterministic trust decision."""

    def __init__(self, config: TrustConfig = DEFAULT_TRUST_CONFIG):
        self.config = config

    def evaluate(
        self,
        events: Iterable[ToolEvent],
        context: SecurityContext,
        policy_decisions: Iterable[PolicyDecision],
        behavior_findings: Iterable[BehaviorFinding],
        invariant_violations: Iterable[InvariantViolation],
        outcome_assessment: OutcomeAssessment,
        risk_assessment: RiskAssessment,
        data_findings: Iterable[DataFinding] = (),
        response_findings: Iterable[ResponseFinding] = (),
    ) -> TrustAssessment:
        """Evaluate all signals to produce a unified TrustAssessment."""
        
        reasons = []
        # Define defaults for the except block
        policy_status = "UNKNOWN"
        behavior_status = "UNKNOWN"
        invariant_status = "UNKNOWN"
        outcome_status = "UNKNOWN"
        evidence = {}
        findings_tuple = ()
        violations_tuple = ()
        
        try:
            findings_tuple = tuple(f.finding_id for f in behavior_findings)
            violations_tuple = tuple(v.invariant_id for v in invariant_violations)
            
            policy_status = "PASS"
            has_deny_decision = False
            for dec in policy_decisions:
                if dec.action in (PolicyAction.DENY, PolicyAction.REQUIRE_APPROVAL):
                    has_deny_decision = True
                    
            # Also check events for DENIED status which indicates an actual block
            from agentguard.execution.models import ExecutionStatus
            has_denied_event = any(e.execution_status == ExecutionStatus.DENIED for e in events)

            if has_deny_decision or has_denied_event:
                policy_status = "DENIED"
                
            has_data_findings = bool(data_findings) or bool(response_findings)
            behavior_status = "CLEAN" if not behavior_findings and not has_data_findings else "FLAGGED"
            invariant_status = "PASS" if not invariant_violations else "VIOLATED"
            outcome_status = "SATISFIED" if outcome_assessment.satisfied else "NOT_SATISFIED"
            
            evidence = {}
            for key in outcome_assessment.observed_evidence:
                evidence[key] = True
            for key in outcome_assessment.missing_evidence:
                evidence[key] = False
            for key in outcome_assessment.failed_evidence:
                evidence[key] = False

            # 1. ERROR checks
            # No explicit errors defined in inputs yet unless there's an exception, which we handle generically.
            # So we proceed to precedence.
            # 2. BLOCKED
            # Blocked by Policy
            is_blocked = False
            
            if has_denied_event or has_deny_decision:
                is_blocked = True
                reasons.append("Execution was blocked by security policy.")
                
            # Blocked by Invariant
            for violation in invariant_violations:
                if violation.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    is_blocked = True
                    reasons.append(f"Execution was blocked by security invariant: {violation.invariant_id}.")

            # Blocked by DataFlow or Response findings
            for df in data_findings:
                if df.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    is_blocked = True
                    reasons.append(f"Execution was blocked by data flow security: {df.title}.")
            for rf in response_findings:
                if rf.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    is_blocked = True
                    reasons.append(f"Execution was blocked by response security: {rf.type}.")

            if is_blocked:
                return self._build_assessment(
                    decision=TrustDecision.BLOCKED,
                    context=context,
                    risk_assessment=risk_assessment,
                    policy_status=policy_status,
                    behavior_status=behavior_status,
                    invariant_status=invariant_status,
                    outcome_status=outcome_status,
                    reasons=tuple(reasons),
                    evidence=evidence,
                    findings=findings_tuple,
                    violations=violations_tuple
                )

            # 3. RISKY
            is_risky = False
            
            # Check behavior findings for HIGH/CRITICAL severity
            for finding in behavior_findings:
                if finding.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                    is_risky = True
                    reasons.append(f"High severity behavioral finding detected: {finding.rule_id}.")
            
            # Check data/response findings for MEDIUM/LOW (High/Critical are handled in blocked)
            for df in data_findings:
                if df.severity in (RiskLevel.MEDIUM, RiskLevel.LOW):
                    is_risky = True
                    reasons.append(f"Risky data flow finding detected: {df.title}.")
            for rf in response_findings:
                if rf.severity in (RiskLevel.MEDIUM, RiskLevel.LOW):
                    is_risky = True
                    reasons.append(f"Risky response finding detected: {rf.type}.")
                    
            # Check risk score threshold
            if risk_assessment.score >= self.config.risky_score_threshold:
                is_risky = True
                reasons.append(f"Risk score ({risk_assessment.score}) exceeds risky threshold ({self.config.risky_score_threshold}).")
                
            if is_risky:
                if not reasons:
                    reasons.append("Execution completed or remained allowed, but the trajectory contains security risk indicators.")
                return self._build_assessment(
                    decision=TrustDecision.RISKY,
                    context=context,
                    risk_assessment=risk_assessment,
                    policy_status=policy_status,
                    behavior_status=behavior_status,
                    invariant_status=invariant_status,
                    outcome_status=outcome_status,
                    reasons=tuple(reasons),
                    evidence=evidence,
                    findings=findings_tuple,
                    violations=violations_tuple
                )
                
            # 4. UNVERIFIED
            # No security violations, but required evidence is missing or task wasn't satisfied.
            if not outcome_assessment.satisfied:
                reasons.append("Required task outcome evidence was not established.")
                return self._build_assessment(
                    decision=TrustDecision.UNVERIFIED,
                    context=context,
                    risk_assessment=risk_assessment,
                    policy_status=policy_status,
                    behavior_status=behavior_status,
                    invariant_status=invariant_status,
                    outcome_status=outcome_status,
                    reasons=tuple(reasons),
                    evidence=evidence,
                    findings=findings_tuple,
                    violations=violations_tuple
                )
                
            # 5. TRUSTED
            reasons.append("All required security checks passed and required task evidence was observed.")
            return self._build_assessment(
                decision=TrustDecision.TRUSTED,
                context=context,
                risk_assessment=risk_assessment,
                policy_status=policy_status,
                behavior_status=behavior_status,
                invariant_status=invariant_status,
                outcome_status=outcome_status,
                reasons=tuple(reasons),
                evidence=evidence,
                findings=findings_tuple,
                violations=violations_tuple
            )

        except Exception:
            # ERROR condition
            return self._build_assessment(
                decision=TrustDecision.ERROR,
                context=context,
                risk_assessment=risk_assessment,
                policy_status=policy_status,
                behavior_status=behavior_status,
                invariant_status=invariant_status,
                outcome_status=outcome_status,
                reasons=("Trust assessment could not be completed.",),
                evidence=evidence,
                findings=findings_tuple,
                violations=violations_tuple
            )
            
    def _build_assessment(
        self,
        decision: TrustDecision,
        context: SecurityContext,
        risk_assessment: RiskAssessment,
        policy_status: str,
        behavior_status: str,
        invariant_status: str,
        outcome_status: str,
        reasons: tuple[str, ...],
        evidence: dict[str, bool],
        findings: tuple[str, ...],
        violations: tuple[str, ...]
    ) -> TrustAssessment:
        confidence = 1.00 if decision != TrustDecision.ERROR else 0.00
        
        # Deduplicate reasons deterministically
        unique_reasons = []
        for r in reasons:
            if r not in unique_reasons:
                unique_reasons.append(r)
                
        # Handle cases where risk_assessment is None in ERROR path
        risk_score = risk_assessment.score if risk_assessment else 0
        risk_severity = risk_assessment.severity.name if risk_assessment else "UNKNOWN"
        
        return TrustAssessment(
            decision=decision,
            session_id=context.session_id if context else "UNKNOWN",
            agent_id=context.agent_id if context else "UNKNOWN",
            task_contract_id=context.task_contract.contract_id if (context and context.task_contract) else None,
            risk_score=risk_score,
            risk_severity=risk_severity,
            policy_status=policy_status,
            behavior_status=behavior_status,
            invariant_status=invariant_status,
            outcome_status=outcome_status,
            confidence=confidence,
            reasons=tuple(unique_reasons),
            evidence=evidence,
            findings=findings,
            violations=violations
        )
