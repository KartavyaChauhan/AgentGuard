"""Deterministic trajectory risk evaluation engine."""

from typing import Iterable

from agentguard.events.models import ToolEvent
from agentguard.behavior.models import BehaviorFinding
from agentguard.risk.models import (
    RiskAssessment, RiskContribution, RiskSeverity, RiskTrend
)
from agentguard.risk.rules import evaluate_event, evaluate_finding
from agentguard.execution.models import ExecutionStatus

class TrajectoryRiskEngine:
    """Evaluates the accumulated security risk of an agent session."""

    def __init__(self, decay_enabled: bool = False):
        self.decay_enabled = decay_enabled
        self._history: dict[str, list[RiskAssessment]] = {}

    def evaluate(self, session_id: str, events: Iterable[ToolEvent], findings: Iterable[BehaviorFinding]) -> RiskAssessment:
        """Evaluate the trajectory risk for a given session."""
        contributions: list[RiskContribution] = []
        
        seen_event_ids = set()
        seen_finding_ids = set()

        has_sensitive_read = False
        has_network = False
        has_shell = False
        has_encoding = False
        has_privileged = False
        has_normal = False
        failures_count = 0
        safe_events_since_risky = 0

        # Evaluate events
        for event in events:
            points, reason = evaluate_event(event)
            
            if points > 0:
                if event.event_id not in seen_event_ids:
                    contributions.append(RiskContribution(
                        source_type="event",
                        source_id=event.event_id,
                        points=points,
                        reason=reason
                    ))
                    seen_event_ids.add(event.event_id)
                safe_events_since_risky = 0
            else:
                safe_events_since_risky += 1
                has_normal = True

            tool = event.tool_name
            if tool == "read_file" and "Sensitive file access" in reason:
                has_sensitive_read = True
            elif tool in ("http_request", "fetch", "curl"):
                has_network = True
            elif tool in ("shell", "bash", "cmd", "run_command"):
                has_shell = True
            elif tool in ("base64_encode", "encode"):
                has_encoding = True
            elif tool == "sudo" or tool.startswith("privileged_"):
                has_privileged = True
                
            if event.execution_status == ExecutionStatus.FAILED:
                failures_count += 1
                
        # Evaluate findings
        for finding in findings:
            points, reason = evaluate_finding(finding)
            if points > 0 and finding.finding_id not in seen_finding_ids:
                contributions.append(RiskContribution(
                    source_type="finding",
                    source_id=finding.finding_id,
                    points=points,
                    reason=reason
                ))
                seen_finding_ids.add(finding.finding_id)

        # Combination bonuses
        combos = []
        
        # 1. Sensitive read + encoding + network (+30) vs Sensitive read + network (+20)
        if has_sensitive_read and has_encoding and has_network:
            combos.append(("combo:sensitive_encode_net", 30, "Sensitive data -> encoding -> network"))
        elif has_sensitive_read and has_network:
            combos.append(("combo:sensitive_net", 20, "Sensitive file access + network request"))
            
        # 2. read_file + shell + network (+25)
        if has_sensitive_read and has_shell and has_network:
            combos.append(("combo:read_shell_net", 25, "read_file + shell + network"))
            
        # 3. normal + privileged (+20)
        if has_normal and has_privileged:
            combos.append(("combo:normal_priv", 20, "Normal operation + privileged operation"))
            
        # 4. Repeated failures (+15)
        if failures_count >= 3:
            combos.append(("combo:failures", 15, "Repeated failures >= 3"))

        combo_points_total = 0
        for combo_id, pts, reason in combos:
            combo_points_total += pts
            contributions.append(RiskContribution(
                source_type="combination",
                source_id=combo_id,
                points=pts,
                reason=reason
            ))

        # Sort contributions deterministically: by points (desc), then reason, then source_id
        contributions.sort(key=lambda c: (-c.points, c.reason, c.source_id))

        # Decay logic
        decay_points = 0
        if self.decay_enabled and safe_events_since_risky > 0:
            # Each safe event since the last risky event: -5 points
            decay_points = -5 * safe_events_since_risky

        # Calculate raw score
        raw_score = sum(c.points for c in contributions)
        
        # Do not allow decay to erase an active critical combination 
        # (assume critical combination = any combo >= 30, or combo_points_total)
        # To be safe, we floor the decayed score at combo_points_total if there are combos
        min_score_allowed = combo_points_total
        
        score = raw_score + decay_points
        if score < min_score_allowed:
            score = min_score_allowed
        
        # Clamp to 0-100
        if score < 0:
            score = 0
        if score > 100:
            score = 100

        # Severity
        if score <= 24:
            severity = RiskSeverity.LOW
        elif score <= 49:
            severity = RiskSeverity.MEDIUM
        elif score <= 74:
            severity = RiskSeverity.HIGH
        else:
            severity = RiskSeverity.CRITICAL

        # Trend analysis
        previous_assessments = self._history.get(session_id, [])
        trend = RiskTrend.STABLE
        if previous_assessments:
            prev_score = previous_assessments[-1].score
            if score > prev_score:
                trend = RiskTrend.INCREASING
            elif score < prev_score:
                trend = RiskTrend.DECREASING

        # Reasons extraction
        reasons = [c.reason for c in contributions]
        if decay_points < 0:
            reasons.append(f"Decay applied: {decay_points} points")

        assessment = RiskAssessment(
            session_id=session_id,
            score=score,
            severity=severity,
            trend=trend,
            contributions=tuple(contributions),
            reasons=tuple(reasons)
        )

        # Store in history
        if session_id not in self._history:
            self._history[session_id] = []
        self._history[session_id].append(assessment)

        return assessment
