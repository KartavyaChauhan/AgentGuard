"""Built-in policy rule types.

Each rule is a frozen dataclass that knows how to match a
:class:`~agentguard.policy.models.ToolRequest` and produce a
:class:`~agentguard.policy.models.PolicyDecision`.

Rules are deliberately simple — no DSL, no YAML parsing.  A future
iteration will add file-based configuration on top of these primitives.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from agentguard.policy.models import (
    PolicyAction,
    PolicyDecision,
    RiskLevel,
    ToolRequest,
)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PolicyRule(ABC):
    """Base class for all policy rules.

    Attributes
    ----------
    id:
        Unique, human-readable identifier for the rule.
    description:
        Short explanation of what the rule does.
    priority:
        Higher values are evaluated first.  Rules with equal priority
        are evaluated in declaration order.
    action:
        The :class:`PolicyAction` to return when the rule matches.
    risk_level:
        Risk level attached to the resulting decision.
    """

    id: str
    description: str
    priority: int = 0
    action: PolicyAction = PolicyAction.DENY
    risk_level: RiskLevel = RiskLevel.HIGH

    @abstractmethod
    def matches(self, request: ToolRequest) -> bool:
        """Return ``True`` if this rule applies to *request*."""

    def decide(self, request: ToolRequest) -> PolicyDecision:
        """Build a :class:`PolicyDecision` for a matching request."""
        return PolicyDecision(
            action=self.action,
            reason=self.description,
            rule_id=self.id,
            risk_level=self.risk_level,
        )


# ---------------------------------------------------------------------------
# Concrete rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolNameRule(PolicyRule):
    """Matches when :attr:`ToolRequest.tool_name` equals *tool_name*.

    Example — deny all ``shell`` invocations::

        ToolNameRule(
            id="deny-shell",
            description="Shell access is denied.",
            tool_name="shell",
        )
    """

    tool_name: str = ""

    def matches(self, request: ToolRequest) -> bool:
        return request.tool_name == self.tool_name


@dataclass(frozen=True, slots=True)
class ArgumentPatternRule(PolicyRule):
    """Matches when a specific argument value contains *pattern*.

    Parameters
    ----------
    tool_name:
        Only match requests for this tool.  Empty string matches any tool.
    argument:
        The key inside :attr:`ToolRequest.arguments` to inspect.
    pattern:
        A substring or regex pattern to search for in the argument value.
    is_regex:
        If ``True``, *pattern* is compiled as a regular expression.
        Defaults to ``False`` (plain substring match).
    """

    tool_name: str = ""
    argument: str = ""
    pattern: str = ""
    is_regex: bool = False

    # Pre-compiled regex (computed lazily via property to keep the dataclass
    # frozen).  We store nothing extra in __init__; the property compiles on
    # first access and we accept the tiny per-call cost for simplicity.

    def _match_value(self, value: str) -> bool:
        if self.is_regex:
            return re.search(self.pattern, value) is not None
        return self.pattern in value

    def matches(self, request: ToolRequest) -> bool:
        # Optionally filter by tool name.
        if self.tool_name and request.tool_name != self.tool_name:
            return False

        raw: Any = request.arguments.get(self.argument)
        if raw is None:
            return False

        return self._match_value(str(raw))


@dataclass(frozen=True, slots=True)
class ApprovalRule(PolicyRule):
    """Matches a tool name and returns :attr:`PolicyAction.REQUIRE_APPROVAL`.

    Convenience subclass that defaults *action* to ``REQUIRE_APPROVAL`` and
    *risk_level* to ``MEDIUM``.

    Example::

        ApprovalRule(
            id="approve-force-push",
            description="Force pushes require human approval.",
            tool_name="git_push_force",
        )
    """

    tool_name: str = ""
    action: PolicyAction = PolicyAction.REQUIRE_APPROVAL
    risk_level: RiskLevel = RiskLevel.MEDIUM

    def matches(self, request: ToolRequest) -> bool:
        return request.tool_name == self.tool_name
