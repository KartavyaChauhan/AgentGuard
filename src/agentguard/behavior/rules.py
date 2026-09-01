"""Deterministic behavioral rules for sequence analysis."""

from __future__ import annotations

import abc
import uuid
from typing import Sequence

from agentguard.events.models import ToolEvent
from agentguard.execution.models import ExecutionStatus
from agentguard.policy.models import RiskLevel
from agentguard.behavior.models import BehaviorFinding


class BehaviorRule(abc.ABC):
    """Abstract base class for a deterministic behavioral rule."""

    @property
    @abc.abstractmethod
    def id(self) -> str:
        """Unique identifier for the rule."""
        pass

    @abc.abstractmethod
    def evaluate(self, events: Sequence[ToolEvent]) -> Sequence[BehaviorFinding]:
        """Evaluate a sequence of events and return any findings."""
        pass

    def _create_finding(
        self,
        severity: RiskLevel,
        title: str,
        description: str,
        event_ids: tuple[str, ...],
        evidence: dict,
        confidence: float,
    ) -> BehaviorFinding:
        """Helper to construct a BehaviorFinding."""
        return BehaviorFinding(
            finding_id=uuid.uuid4().hex,
            rule_id=self.id,
            severity=severity,
            title=title,
            description=description,
            event_ids=event_ids,
            evidence=evidence,
            confidence=confidence,
        )


class SensitiveDataToNetworkRule(BehaviorRule):
    """RULE 1: Sensitive Data → External Network."""

    def __init__(
        self,
        sensitive_indicators: set[str] | None = None,
        network_tools: set[str] | None = None,
    ) -> None:
        self.sensitive_indicators = sensitive_indicators or {
            ".env", "credentials", "secret", "private_key", "api_key", "token"
        }
        self.network_tools = network_tools or {
            "http_request", "send_http_request", "fetch", "curl", "wget", "request"
        }

    @property
    def id(self) -> str:
        return "sensitive-data-to-network"

    def _is_sensitive(self, event: ToolEvent) -> str | None:
        """Returns the indicator matched if the event is sensitive, else None."""
        # Simple string matching in arguments (keys or values)
        for indicator in self.sensitive_indicators:
            for k, v in event.arguments.items():
                if indicator in str(k).lower() or indicator in str(v).lower():
                    return indicator
        return None

    def evaluate(self, events: Sequence[ToolEvent]) -> Sequence[BehaviorFinding]:
        findings = []
        sensitive_event = None
        sensitive_indicator = None

        for event in events:
            # Only consider EXECUTED tools (or at least attempted)
            if event.execution_status == ExecutionStatus.DENIED:
                continue

            if not sensitive_event:
                indicator = self._is_sensitive(event)
                if indicator:
                    sensitive_event = event
                    sensitive_indicator = indicator
            else:
                if event.tool_name in self.network_tools:
                    findings.append(
                        self._create_finding(
                            severity=RiskLevel.HIGH,
                            title="Sensitive data followed by network transfer",
                            description="A sensitive resource was accessed and a network operation occurred later in the same session.",
                            event_ids=(sensitive_event.event_id, event.event_id),
                            evidence={
                                "sensitive_tool": sensitive_event.tool_name,
                                "sensitive_indicator": sensitive_indicator,
                                "network_tool": event.tool_name,
                            },
                            confidence=0.85,
                        )
                    )
                    # Reset after finding to avoid spamming or find multiple distinct chains?
                    # Let's reset to find the next chain if it occurs.
                    sensitive_event = None
                    sensitive_indicator = None

        return findings


class EncodingBeforeNetworkRule(BehaviorRule):
    """RULE 2: Encoding Before Network Transfer."""

    def __init__(
        self,
        sensitive_indicators: set[str] | None = None,
        encoding_tools: set[str] | None = None,
        network_tools: set[str] | None = None,
    ) -> None:
        self.sensitive_indicators = sensitive_indicators or {
            ".env", "credentials", "secret", "private_key", "api_key", "token"
        }
        self.encoding_tools = encoding_tools or {
            "base64_encode", "encode", "zip", "tar", "compress", "encrypt"
        }
        self.network_tools = network_tools or {
            "http_request", "send_http_request", "fetch", "curl", "wget", "request"
        }

    @property
    def id(self) -> str:
        return "encoding-before-network"

    def _is_sensitive(self, event: ToolEvent) -> str | None:
        for indicator in self.sensitive_indicators:
            for k, v in event.arguments.items():
                if indicator in str(k).lower() or indicator in str(v).lower():
                    return indicator
        return None

    def evaluate(self, events: Sequence[ToolEvent]) -> Sequence[BehaviorFinding]:
        findings = []
        
        # State machine
        sensitive_event = None
        encoding_event = None
        sensitive_indicator = None

        for event in events:
            if event.execution_status == ExecutionStatus.DENIED:
                continue

            if not sensitive_event:
                indicator = self._is_sensitive(event)
                if indicator:
                    sensitive_event = event
                    sensitive_indicator = indicator
            elif not encoding_event:
                if event.tool_name in self.encoding_tools:
                    encoding_event = event
                else:
                    # Could allow intervening tools or reset?
                    # Let's allow intervening tools since "after" is usually non-strict
                    pass
            else:
                if event.tool_name in self.network_tools:
                    findings.append(
                        self._create_finding(
                            severity=RiskLevel.CRITICAL,
                            title="Sensitive data encoded before network transfer",
                            description="Sensitive data was read, encoded/transformed, and then a network operation occurred.",
                            event_ids=(sensitive_event.event_id, encoding_event.event_id, event.event_id),
                            evidence={
                                "sensitive_tool": sensitive_event.tool_name,
                                "sensitive_indicator": sensitive_indicator,
                                "encoding_tool": encoding_event.tool_name,
                                "network_tool": event.tool_name,
                            },
                            confidence=0.95,
                        )
                    )
                    sensitive_event = None
                    encoding_event = None
                    sensitive_indicator = None

        return findings


class PrivilegeEscalationRule(BehaviorRule):
    """RULE 3: Privilege Escalation Sequence."""

    def __init__(self, privileged_indicators: set[str] | None = None) -> None:
        self.privileged_indicators = privileged_indicators or {
            "sudo", "admin", "root", "shell", "execute_command", "chmod", "permission_change"
        }

    @property
    def id(self) -> str:
        return "privilege-escalation"

    def _is_privileged(self, tool_name: str) -> bool:
        return any(ind in tool_name.lower() for ind in self.privileged_indicators)

    def evaluate(self, events: Sequence[ToolEvent]) -> Sequence[BehaviorFinding]:
        findings = []
        normal_event = None

        for event in events:
            if event.execution_status == ExecutionStatus.DENIED:
                continue

            if self._is_privileged(event.tool_name):
                if normal_event:
                    findings.append(
                        self._create_finding(
                            severity=RiskLevel.HIGH,
                            title="Potential Privilege Escalation",
                            description="A normal tool was followed by a privileged tool execution.",
                            event_ids=(normal_event.event_id, event.event_id),
                            evidence={
                                "normal_tool": normal_event.tool_name,
                                "privileged_tool": event.tool_name,
                            },
                            confidence=0.75,
                        )
                    )
                    normal_event = None # Reset
            else:
                normal_event = event

        return findings


class RepeatedFailureRule(BehaviorRule):
    """RULE 4: Repeated Failure Pattern."""

    def __init__(self, threshold: int = 3) -> None:
        self.threshold = threshold

    @property
    def id(self) -> str:
        return "repeated-failures"

    def evaluate(self, events: Sequence[ToolEvent]) -> Sequence[BehaviorFinding]:
        findings = []
        failed_events = []

        for event in events:
            if event.execution_status == ExecutionStatus.FAILED:
                failed_events.append(event)
                if len(failed_events) >= self.threshold:
                    findings.append(
                        self._create_finding(
                            severity=RiskLevel.MEDIUM,
                            title="Repeated execution failures",
                            description=f"Detected {self.threshold} failed tool executions in a session.",
                            event_ids=tuple(e.event_id for e in failed_events),
                            evidence={
                                "failure_count": len(failed_events),
                                "tools": [e.tool_name for e in failed_events],
                            },
                            confidence=0.90,
                        )
                    )
                    failed_events = [] # Reset
            else:
                # Optionally reset consecutive failures if a success happens, 
                # but rule says "Detect repeated failed executions in a session".
                # For anomaly detection, consecutive is usually better. Let's do consecutive.
                failed_events = []

        return findings


class SuspiciousToolChainRule(BehaviorRule):
    """RULE 5: Suspicious Tool Chain."""

    def __init__(self, sequence: list[str] | None = None) -> None:
        # Default chain: read_file -> shell -> network_request
        self.sequence = sequence or ["read_file", "shell", "network_request"]

    @property
    def id(self) -> str:
        return "suspicious-tool-chain"

    def evaluate(self, events: Sequence[ToolEvent]) -> Sequence[BehaviorFinding]:
        if not self.sequence:
            return []

        findings = []
        state_idx = 0
        chain_events = []

        for event in events:
            if event.execution_status == ExecutionStatus.DENIED:
                continue

            # Look for substring match in tool name to support variations
            # e.g., "shell" matching "run_shell"
            if self.sequence[state_idx] in event.tool_name:
                chain_events.append(event)
                state_idx += 1
                
                if state_idx == len(self.sequence):
                    findings.append(
                        self._create_finding(
                            severity=RiskLevel.HIGH,
                            title="Suspicious tool chain detected",
                            description=f"A known suspicious sequence of tools was executed: {' -> '.join(self.sequence)}",
                            event_ids=tuple(e.event_id for e in chain_events),
                            evidence={
                                "chain": [e.tool_name for e in chain_events],
                                "matched_sequence": self.sequence,
                            },
                            confidence=0.80,
                        )
                    )
                    # Reset state
                    state_idx = 0
                    chain_events = []
            else:
                # If interrupted by unrelated tool, do we break the chain?
                # Sequences can have gaps, so we don't necessarily reset.
                pass

        return findings
