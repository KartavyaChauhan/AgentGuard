"""Deterministic policy evaluation engine.

The :class:`PolicyEngine` accepts a sequence of :class:`PolicyRule` instances,
sorts them by priority (highest first, stable), and evaluates them in order
against a :class:`ToolRequest`.

Evaluation semantics
--------------------
* **First match wins** — the first rule (by priority, then declaration order)
  whose :meth:`~PolicyRule.matches` returns ``True`` produces the decision.
* **Default allow** — if no rule matches, the engine returns ``ALLOW`` with
  risk level ``LOW``.
* **Fail closed per rule** — if a rule's ``matches()`` raises an unexpected
  exception the engine treats that rule as matching with ``DENY`` and logs the
  error, but continues to return a decision rather than crashing.
"""

from __future__ import annotations

from agentguard.logging import get_logger
from agentguard.policy.models import (
    PolicyAction,
    PolicyDecision,
    RiskLevel,
    ToolRequest,
)
from agentguard.policy.rules import PolicyRule

logger = get_logger(__name__)


class PolicyEngine:
    """Evaluate a :class:`ToolRequest` against an ordered set of rules.

    Parameters
    ----------
    rules:
        Policy rules to enforce.  They are sorted internally by descending
        priority; declaration order is preserved for rules with equal priority.
    """

    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        # ``sorted`` is stable, so equal-priority rules keep their
        # declaration order.
        self._rules: list[PolicyRule] = sorted(
            rules or [],
            key=lambda r: r.priority,
            reverse=True,
        )

    @property
    def rules(self) -> list[PolicyRule]:
        """Return the evaluated rule list (sorted, read-only copy)."""
        return list(self._rules)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    _DEFAULT_ALLOW = PolicyDecision(
        action=PolicyAction.ALLOW,
        reason="No matching rule — default allow.",
        rule_id=None,
        risk_level=RiskLevel.LOW,
    )

    def evaluate(self, request: ToolRequest) -> PolicyDecision:
        """Evaluate *request* against all rules and return a decision.

        Returns
        -------
        PolicyDecision
            The decision from the first matching rule, or a default
            ``ALLOW`` if no rules match.
        """
        for rule in self._rules:
            try:
                if rule.matches(request):
                    decision = rule.decide(request)
                    logger.info(
                        "Rule matched",
                        extra={
                            "rule_id": rule.id,
                            "tool": request.tool_name,
                            "action": decision.action.value,
                        },
                    )
                    return decision
            except Exception:
                # Fail closed for this rule — treat an evaluation error as
                # a DENY so a buggy rule cannot silently allow dangerous
                # actions.
                logger.exception(
                    "Rule evaluation error — failing closed",
                    extra={"rule_id": rule.id, "tool": request.tool_name},
                )
                return PolicyDecision(
                    action=PolicyAction.DENY,
                    reason=(
                        f"Rule '{rule.id}' encountered an evaluation error; "
                        f"failing closed."
                    ),
                    rule_id=rule.id,
                    risk_level=RiskLevel.CRITICAL,
                )

        return self._DEFAULT_ALLOW
