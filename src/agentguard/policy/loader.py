"""Policy rule loader for AgentGuard.

Provides functionality to load and validate policy rules from built-in
specifications or custom JSON policy configuration files.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any

from agentguard.policy.defaults import DEFAULT_RULES
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.policy.rules import (
    ApprovalRule,
    ArgumentPatternRule,
    PolicyRule,
    ToolNameRule,
)


class PolicyConfigurationError(ValueError):
    """Raised when policy configuration or rule definition is invalid."""


_ALLOWED_RULE_FIELDS: dict[str, set[str]] = {
    "tool_name": {
        "type",
        "id",
        "description",
        "tool_name",
        "priority",
        "action",
        "risk_level",
    },
    "argument_pattern": {
        "type",
        "id",
        "description",
        "tool_name",
        "argument",
        "pattern",
        "is_regex",
        "priority",
        "action",
        "risk_level",
    },
    "approval": {
        "type",
        "id",
        "description",
        "tool_name",
        "priority",
        "action",
        "risk_level",
    },
}


def _validate_string(val: Any, field_name: str, rule_identifier: str, allow_empty: bool = False) -> str:
    """Validate that val is a string and optionally non-empty without type coercion."""
    if type(val) is not str:
        raise PolicyConfigurationError(
            f"Rule '{rule_identifier}' field '{field_name}' must be a string, got {type(val).__name__}."
        )
    if not allow_empty and not val.strip():
        raise PolicyConfigurationError(
            f"Rule '{rule_identifier}' field '{field_name}' must not be empty or whitespace."
        )
    return val


def _validate_priority(val: Any, rule_identifier: str) -> int:
    """Validate priority as an integer without boolean coercion."""
    if type(val) is not int:
        raise PolicyConfigurationError(
            f"Rule '{rule_identifier}' priority must be an integer, got {type(val).__name__}."
        )
    return val


def _validate_action(val: Any, rule_identifier: str) -> PolicyAction:
    """Validate action against PolicyAction enum."""
    if type(val) is not str:
        raise PolicyConfigurationError(
            f"Rule '{rule_identifier}' action must be a string, got {type(val).__name__}."
        )
    action_key = val.strip().upper()
    if action_key not in PolicyAction.__members__:
        valid_actions = ", ".join(sorted(PolicyAction.__members__.keys()))
        raise PolicyConfigurationError(
            f"Rule '{rule_identifier}' has invalid action '{val}'. Valid actions: {valid_actions}."
        )
    return PolicyAction[action_key]


def _validate_risk_level(val: Any, rule_identifier: str) -> RiskLevel:
    """Validate risk level against RiskLevel enum."""
    if type(val) is not str:
        raise PolicyConfigurationError(
            f"Rule '{rule_identifier}' risk_level must be a string, got {type(val).__name__}."
        )
    risk_key = val.strip().upper()
    if risk_key not in RiskLevel.__members__:
        valid_levels = ", ".join(sorted(RiskLevel.__members__.keys()))
        raise PolicyConfigurationError(
            f"Rule '{rule_identifier}' has invalid risk_level '{val}'. Valid risk levels: {valid_levels}."
        )
    return RiskLevel[risk_key]


def parse_policy_dict(data: Any, source: str = "<data>") -> list[PolicyRule]:
    """Parse and validate a dictionary containing policy rules.

    Parameters
    ----------
    data:
        Parsed JSON document root.
    source:
        Origin identifier used for error reporting (e.g. file path).

    Returns
    -------
    list[PolicyRule]
        A list of validated PolicyRule instances in declaration order.

    Raises
    ------
    PolicyConfigurationError
        If the document structure, rule fields, or types are invalid.
    """
    if type(data) is not dict:
        raise PolicyConfigurationError(
            f"Policy document in {source} must have a JSON object as root, got {type(data).__name__}."
        )

    if "rules" not in data:
        raise PolicyConfigurationError(
            f"Policy document in {source} missing required 'rules' field."
        )

    raw_rules = data["rules"]
    if type(raw_rules) is not list:
        raise PolicyConfigurationError(
            f"The 'rules' field in {source} must be an array, got {type(raw_rules).__name__}."
        )

    if len(raw_rules) == 0:
        raise PolicyConfigurationError(
            f"The 'rules' array in {source} must not be empty."
        )

    rules: list[PolicyRule] = []
    seen_ids: set[str] = set()

    for idx, rule_data in enumerate(raw_rules):
        rule_ident = f"index {idx}"
        if type(rule_data) is not dict:
            raise PolicyConfigurationError(
                f"Rule at {rule_ident} in {source} must be an object, got {type(rule_data).__name__}."
            )

        # Validate type
        if "type" not in rule_data:
            raise PolicyConfigurationError(
                f"Rule at {rule_ident} in {source} missing required field 'type'."
            )
        rule_type = rule_data["type"]
        if type(rule_type) is not str:
            raise PolicyConfigurationError(
                f"Rule at {rule_ident} in {source} field 'type' must be a string, got {type(rule_type).__name__}."
            )
        if rule_type not in _ALLOWED_RULE_FIELDS:
            supported = ", ".join(sorted(_ALLOWED_RULE_FIELDS.keys()))
            raise PolicyConfigurationError(
                f"Rule at {rule_ident} in {source} has unsupported type '{rule_type}'. Supported types: {supported}."
            )

        # Validate ID
        if "id" not in rule_data:
            raise PolicyConfigurationError(
                f"Rule at {rule_ident} in {source} missing required field 'id'."
            )
        rule_id = _validate_string(rule_data["id"], "id", rule_ident)
        if rule_id in seen_ids:
            raise PolicyConfigurationError(
                f"Duplicate rule ID '{rule_id}' at index {idx} in {source}."
            )
        seen_ids.add(rule_id)
        rule_ident = rule_id

        # Check for unknown fields
        allowed = _ALLOWED_RULE_FIELDS[rule_type]
        unknown = set(rule_data.keys()) - allowed
        if unknown:
            sorted_unknown = ", ".join(sorted(unknown))
            raise PolicyConfigurationError(
                f"Rule '{rule_id}' in {source} contains unknown field(s): {sorted_unknown}."
            )

        # Validate description
        if "description" not in rule_data:
            raise PolicyConfigurationError(
                f"Rule '{rule_id}' in {source} missing required field 'description'."
            )
        description = _validate_string(rule_data["description"], "description", rule_id)

        # Priority
        priority = 0
        if "priority" in rule_data:
            priority = _validate_priority(rule_data["priority"], rule_id)

        # Build rule based on type
        if rule_type == "tool_name":
            action = PolicyAction.DENY
            if "action" in rule_data:
                action = _validate_action(rule_data["action"], rule_id)

            risk_level = RiskLevel.HIGH
            if "risk_level" in rule_data:
                risk_level = _validate_risk_level(rule_data["risk_level"], rule_id)

            if "tool_name" not in rule_data:
                raise PolicyConfigurationError(
                    f"Rule '{rule_id}' in {source} missing required field 'tool_name'."
                )
            tool_name = _validate_string(rule_data["tool_name"], "tool_name", rule_id)

            rules.append(
                ToolNameRule(
                    id=rule_id,
                    description=description,
                    priority=priority,
                    action=action,
                    risk_level=risk_level,
                    tool_name=tool_name,
                )
            )

        elif rule_type == "argument_pattern":
            action = PolicyAction.DENY
            if "action" in rule_data:
                action = _validate_action(rule_data["action"], rule_id)

            risk_level = RiskLevel.HIGH
            if "risk_level" in rule_data:
                risk_level = _validate_risk_level(rule_data["risk_level"], rule_id)

            tool_name = ""
            if "tool_name" in rule_data:
                tool_name = _validate_string(
                    rule_data["tool_name"], "tool_name", rule_id, allow_empty=True
                )

            if "argument" not in rule_data:
                raise PolicyConfigurationError(
                    f"Rule '{rule_id}' in {source} missing required field 'argument'."
                )
            argument = _validate_string(rule_data["argument"], "argument", rule_id)

            if "pattern" not in rule_data:
                raise PolicyConfigurationError(
                    f"Rule '{rule_id}' in {source} missing required field 'pattern'."
                )
            if type(rule_data["pattern"]) is not str:
                raise PolicyConfigurationError(
                    f"Rule '{rule_id}' field 'pattern' must be a string, got {type(rule_data['pattern']).__name__}."
                )
            pattern = rule_data["pattern"]
            if len(pattern) == 0:
                raise PolicyConfigurationError(
                    f"Rule '{rule_id}' field 'pattern' must not be empty."
                )

            is_regex = False
            if "is_regex" in rule_data:
                raw_regex = rule_data["is_regex"]
                if type(raw_regex) is not bool:
                    raise PolicyConfigurationError(
                        f"Rule '{rule_id}' field 'is_regex' must be a boolean, got {type(raw_regex).__name__}."
                    )
                is_regex = raw_regex

            if is_regex:
                try:
                    re.compile(pattern)
                except re.error as err:
                    raise PolicyConfigurationError(
                        f"Rule '{rule_id}' in {source} has invalid regular expression '{pattern}': {err}."
                    ) from err

            rules.append(
                ArgumentPatternRule(
                    id=rule_id,
                    description=description,
                    priority=priority,
                    action=action,
                    risk_level=risk_level,
                    tool_name=tool_name,
                    argument=argument,
                    pattern=pattern,
                    is_regex=is_regex,
                )
            )

        elif rule_type == "approval":
            action = PolicyAction.REQUIRE_APPROVAL
            if "action" in rule_data:
                action = _validate_action(rule_data["action"], rule_id)
                if action != PolicyAction.REQUIRE_APPROVAL:
                    raise PolicyConfigurationError(
                        f"Approval rule '{rule_id}' in {source} specifies incompatible action '{rule_data['action']}'. "
                        "Approval rules only support action 'REQUIRE_APPROVAL'."
                    )

            risk_level = RiskLevel.MEDIUM
            if "risk_level" in rule_data:
                risk_level = _validate_risk_level(rule_data["risk_level"], rule_id)

            if "tool_name" not in rule_data:
                raise PolicyConfigurationError(
                    f"Rule '{rule_id}' in {source} missing required field 'tool_name'."
                )
            tool_name = _validate_string(rule_data["tool_name"], "tool_name", rule_id)

            rules.append(
                ApprovalRule(
                    id=rule_id,
                    description=description,
                    priority=priority,
                    action=action,
                    risk_level=risk_level,
                    tool_name=tool_name,
                )
            )

    return rules


def load_policy_rules(spec: str) -> list[PolicyRule]:
    """Load policy rules from built-in specification or a JSON policy file.

    Parameters
    ----------
    spec:
        Either "default" (case-insensitive) for built-in rules, or a file path
        to a JSON policy document. Relative file paths are resolved against
        the process current working directory.

    Returns
    -------
    list[PolicyRule]
        A new list of configured policy rules. Mutating the returned list does
        not alter built-in rules or subsequent loader calls.

    Raises
    ------
    PolicyConfigurationError
        If the policy specification, file, JSON syntax, or rule configuration
        is invalid or cannot be read.
    """
    if type(spec) is not str:
        raise PolicyConfigurationError(
            f"Policy specification must be a string, got {type(spec).__name__}."
        )

    cleaned = spec.strip()
    if not cleaned:
        raise PolicyConfigurationError(
            "Policy specification must not be empty or whitespace."
        )

    # Built-in policy: "default" (case-insensitive)
    if cleaned.lower() == "default":
        return list(DEFAULT_RULES)

    # File-based custom policy: resolve relative paths against process working directory
    policy_path = Path(cleaned).expanduser()
    if not policy_path.is_absolute():
        policy_path = (Path.cwd() / policy_path).resolve()
    else:
        policy_path = policy_path.resolve()

    if not policy_path.exists():
        raise PolicyConfigurationError(
            f"Policy file not found: '{policy_path}'."
        )

    if not policy_path.is_file():
        raise PolicyConfigurationError(
            f"Policy path is not a file: '{policy_path}'."
        )

    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as err:
        raise PolicyConfigurationError(
            f"Cannot read policy file '{policy_path}': {err}."
        ) from err

    try:
        data = json.loads(content)
    except json.JSONDecodeError as err:
        raise PolicyConfigurationError(
            f"Invalid JSON in policy file '{policy_path}': {err}."
        ) from err

    return parse_policy_dict(data, source=str(policy_path))
