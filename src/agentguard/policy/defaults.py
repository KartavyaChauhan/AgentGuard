"""Default policy rules for testing and demonstration.

These rules are **not** loaded automatically by the engine.  They exist as a
reference set that can be passed to :class:`~agentguard.policy.engine.PolicyEngine`
during development or used as a starting point for user-defined policies.

Usage::

    from agentguard.policy import PolicyEngine
    from agentguard.policy.defaults import DEFAULT_RULES

    engine = PolicyEngine(rules=DEFAULT_RULES)
"""

from __future__ import annotations

from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.policy.rules import ApprovalRule, ArgumentPatternRule, ToolNameRule

DEFAULT_RULES: list[ToolNameRule | ArgumentPatternRule | ApprovalRule] = [
    # ------------------------------------------------------------------
    # DENY rules  (priority 100 — evaluated first)
    # ------------------------------------------------------------------
    ArgumentPatternRule(
        id="deny-shell-rm-rf",
        description="Destructive shell command: rm -rf is not allowed.",
        priority=100,
        tool_name="shell",
        argument="command",
        pattern="rm -rf",
        action=PolicyAction.DENY,
        risk_level=RiskLevel.CRITICAL,
    ),
    ArgumentPatternRule(
        id="deny-read-env",
        description="Reading .env files is not allowed.",
        priority=100,
        tool_name="read_file",
        argument="path",
        pattern=".env",
        action=PolicyAction.DENY,
        risk_level=RiskLevel.HIGH,
    ),
    ArgumentPatternRule(
        id="deny-read-credentials",
        description="Reading credentials files is not allowed.",
        priority=100,
        tool_name="read_file",
        argument="path",
        pattern="credentials.json",
        action=PolicyAction.DENY,
        risk_level=RiskLevel.HIGH,
    ),
    ArgumentPatternRule(
        id="deny-read-git",
        description="Reading .git/ directory contents is not allowed.",
        priority=100,
        tool_name="read_file",
        argument="path",
        pattern=r"^\.git/",
        is_regex=True,
        action=PolicyAction.DENY,
        risk_level=RiskLevel.HIGH,
    ),
    ToolNameRule(
        id="deny-sudo",
        description="Unauthorized privilege escalation via sudo is denied.",
        priority=100,
        tool_name="sudo",
        action=PolicyAction.DENY,
        risk_level=RiskLevel.CRITICAL,
    ),
    ArgumentPatternRule(
        id="deny-force-push",
        description="Force pushes are denied.",
        priority=100,
        tool_name="git_push",
        argument="force",
        pattern="True",
        action=PolicyAction.DENY,
        risk_level=RiskLevel.CRITICAL,
    ),
    # ------------------------------------------------------------------
    # REQUIRE_APPROVAL rules  (priority 50)
    # ------------------------------------------------------------------
    ApprovalRule(
        id="approve-force-push",
        description="Require approval for force pushes.",
        tool_name="git_push_force",
        risk_level=RiskLevel.HIGH,
    ),
    ApprovalRule(
        id="approve-dangerous-operation",
        description="Require approval for highly dangerous operations.",
        tool_name="dangerous_operation",
        risk_level=RiskLevel.CRITICAL,
    ),
]
