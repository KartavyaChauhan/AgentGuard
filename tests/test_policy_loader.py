"""Comprehensive tests for the policy loader and gateway configuration integration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agentguard.cli import run_gateway_command
from agentguard.gateway.config import load_config
from agentguard.policy import (
    ApprovalRule,
    ArgumentPatternRule,
    PolicyAction,
    PolicyConfigurationError,
    PolicyEngine,
    RiskLevel,
    ToolNameRule,
    ToolRequest,
    load_policy_rules,
    parse_policy_dict,
)
from agentguard.policy.defaults import DEFAULT_RULES


# ---------------------------------------------------------------------------
# Built-in policy tests
# ---------------------------------------------------------------------------


class TestBuiltinPolicy:
    """Tests for loading built-in 'default' policies."""

    def test_load_default(self) -> None:
        rules = load_policy_rules("default")
        assert len(rules) == len(DEFAULT_RULES)
        assert [r.id for r in rules] == [r.id for r in DEFAULT_RULES]

    @pytest.mark.parametrize("spec", ["DEFAULT", "Default", "  default  ", "DeFaUlT"])
    def test_load_default_case_insensitive(self, spec: str) -> None:
        rules = load_policy_rules(spec)
        assert len(rules) == len(DEFAULT_RULES)

    def test_default_rules_list_is_independent_copy(self) -> None:
        rules1 = load_policy_rules("default")
        rules1.clear()
        assert len(rules1) == 0

        rules2 = load_policy_rules("default")
        assert len(rules2) == len(DEFAULT_RULES)
        assert len(DEFAULT_RULES) > 0

    def test_default_rules_enforcement(self) -> None:
        rules = load_policy_rules("default")
        engine = PolicyEngine(rules=rules)

        # Deny rule
        decision_deny = engine.evaluate(
            ToolRequest(tool_name="shell", arguments={"command": "rm -rf /"})
        )
        assert decision_deny.action == PolicyAction.DENY
        assert decision_deny.rule_id == "deny-shell-rm-rf"

        # Approval rule
        decision_appr = engine.evaluate(ToolRequest(tool_name="git_push_force"))
        assert decision_appr.action == PolicyAction.REQUIRE_APPROVAL
        assert decision_appr.rule_id == "approve-force-push"

        # Allow (default)
        decision_allow = engine.evaluate(
            ToolRequest(tool_name="read_file", arguments={"path": "main.py"})
        )
        assert decision_allow.action == PolicyAction.ALLOW


# ---------------------------------------------------------------------------
# Custom policy tests (Success paths)
# ---------------------------------------------------------------------------


class TestCustomPolicySuccess:
    """Tests for successfully loading and evaluating custom JSON policy rules."""

    def test_valid_tool_name_rule(self, tmp_path: Path) -> None:
        doc = {
            "rules": [
                {
                    "type": "tool_name",
                    "id": "deny-bash",
                    "description": "Block all bash invocations",
                    "tool_name": "bash",
                    "priority": 80,
                    "action": "DENY",
                    "risk_level": "CRITICAL",
                }
            ]
        }
        file_path = tmp_path / "policy.json"
        file_path.write_text(json.dumps(doc), encoding="utf-8")

        rules = load_policy_rules(str(file_path))
        assert len(rules) == 1
        rule = rules[0]
        assert isinstance(rule, ToolNameRule)
        assert rule.id == "deny-bash"
        assert rule.description == "Block all bash invocations"
        assert rule.tool_name == "bash"
        assert rule.priority == 80
        assert rule.action == PolicyAction.DENY
        assert rule.risk_level == RiskLevel.CRITICAL

        engine = PolicyEngine(rules=rules)
        assert engine.evaluate(ToolRequest(tool_name="bash")).action == PolicyAction.DENY
        assert engine.evaluate(ToolRequest(tool_name="sh")).action == PolicyAction.ALLOW

    def test_valid_argument_substring_rule(self, tmp_path: Path) -> None:
        doc = {
            "rules": [
                {
                    "type": "argument_pattern",
                    "id": "block-drop-db",
                    "description": "Prevent dropping databases",
                    "tool_name": "sql_query",
                    "argument": "query",
                    "pattern": "DROP DATABASE",
                    "is_regex": False,
                    "priority": 75,
                    "action": "DENY",
                    "risk_level": "HIGH",
                }
            ]
        }
        file_path = tmp_path / "policy.json"
        file_path.write_text(json.dumps(doc), encoding="utf-8")

        rules = load_policy_rules(str(file_path))
        assert len(rules) == 1
        rule = rules[0]
        assert isinstance(rule, ArgumentPatternRule)
        assert rule.id == "block-drop-db"
        assert rule.tool_name == "sql_query"
        assert rule.argument == "query"
        assert rule.pattern == "DROP DATABASE"
        assert rule.is_regex is False

        engine = PolicyEngine(rules=rules)
        match_req = ToolRequest(tool_name="sql_query", arguments={"query": "DROP DATABASE users;"})
        assert engine.evaluate(match_req).action == PolicyAction.DENY

        safe_req = ToolRequest(tool_name="sql_query", arguments={"query": "SELECT * FROM users;"})
        assert engine.evaluate(safe_req).action == PolicyAction.ALLOW

    def test_valid_argument_regex_rule(self, tmp_path: Path) -> None:
        doc = {
            "rules": [
                {
                    "type": "argument_pattern",
                    "id": "block-secret-keys",
                    "description": "Block AWS secret keys in arguments",
                    "argument": "token",
                    "pattern": r"^AKIA[0-9A-Z]{16}$",
                    "is_regex": True,
                    "priority": 90,
                }
            ]
        }
        file_path = tmp_path / "policy.json"
        file_path.write_text(json.dumps(doc), encoding="utf-8")

        rules = load_policy_rules(str(file_path))
        rule = rules[0]
        assert isinstance(rule, ArgumentPatternRule)
        assert rule.is_regex is True
        assert rule.tool_name == ""  # any tool
        assert rule.action == PolicyAction.DENY  # default action
        assert rule.risk_level == RiskLevel.HIGH  # default risk

        engine = PolicyEngine(rules=rules)
        match_req = ToolRequest(tool_name="http", arguments={"token": "AKIAIOSFODNN7EXAMPLE"})
        assert engine.evaluate(match_req).action == PolicyAction.DENY

        non_match = ToolRequest(tool_name="http", arguments={"token": "not-a-key"})
        assert engine.evaluate(non_match).action == PolicyAction.ALLOW

    def test_valid_approval_rule_defaults(self, tmp_path: Path) -> None:
        doc = {
            "rules": [
                {
                    "type": "approval",
                    "id": "approve-reboot",
                    "description": "Server reboot requires human approval",
                    "tool_name": "reboot_server",
                }
            ]
        }
        file_path = tmp_path / "policy.json"
        file_path.write_text(json.dumps(doc), encoding="utf-8")

        rules = load_policy_rules(str(file_path))
        rule = rules[0]
        assert isinstance(rule, ApprovalRule)
        assert rule.id == "approve-reboot"
        assert rule.action == PolicyAction.REQUIRE_APPROVAL
        assert rule.risk_level == RiskLevel.MEDIUM
        assert rule.priority == 0

        engine = PolicyEngine(rules=rules)
        assert engine.evaluate(ToolRequest(tool_name="reboot_server")).action == PolicyAction.REQUIRE_APPROVAL

    def test_valid_approval_rule_explicit_action_and_risk(self, tmp_path: Path) -> None:
        doc = {
            "rules": [
                {
                    "type": "approval",
                    "id": "approve-deploy",
                    "description": "Production deploy approval",
                    "tool_name": "deploy_prod",
                    "priority": 150,
                    "action": "REQUIRE_APPROVAL",
                    "risk_level": "CRITICAL",
                }
            ]
        }
        file_path = tmp_path / "policy.json"
        file_path.write_text(json.dumps(doc), encoding="utf-8")

        rules = load_policy_rules(str(file_path))
        rule = rules[0]
        assert isinstance(rule, ApprovalRule)
        assert rule.priority == 150
        assert rule.action == PolicyAction.REQUIRE_APPROVAL
        assert rule.risk_level == RiskLevel.CRITICAL

    def test_multiple_rules_priority_and_declaration_order(self, tmp_path: Path) -> None:
        doc = {
            "rules": [
                {
                    "type": "tool_name",
                    "id": "first-equal",
                    "description": "First rule with priority 50",
                    "tool_name": "test_tool",
                    "priority": 50,
                    "action": "DENY",
                },
                {
                    "type": "tool_name",
                    "id": "second-equal",
                    "description": "Second rule with priority 50",
                    "tool_name": "test_tool",
                    "priority": 50,
                    "action": "REQUIRE_APPROVAL",
                },
                {
                    "type": "tool_name",
                    "id": "high-priority",
                    "description": "Rule with priority 100",
                    "tool_name": "test_tool",
                    "priority": 100,
                    "action": "ALLOW",
                },
            ]
        }
        file_path = tmp_path / "policy.json"
        file_path.write_text(json.dumps(doc), encoding="utf-8")

        rules = load_policy_rules(str(file_path))
        assert len(rules) == 3
        # In declaration order from loader
        assert [r.id for r in rules] == ["first-equal", "second-equal", "high-priority"]

        # PolicyEngine sorts by descending priority
        engine = PolicyEngine(rules=rules)
        dec = engine.evaluate(ToolRequest(tool_name="test_tool"))
        assert dec.rule_id == "high-priority"
        assert dec.action == PolicyAction.ALLOW

    def test_path_with_spaces_and_relative_resolution(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        sub_dir = tmp_path / "policies with spaces"
        sub_dir.mkdir()
        file_path = sub_dir / "custom rules.json"
        doc = {
            "rules": [
                {
                    "type": "tool_name",
                    "id": "deny-spaces",
                    "description": "Test path with spaces",
                    "tool_name": "space_tool",
                }
            ]
        }
        file_path.write_text(json.dumps(doc), encoding="utf-8")

        monkeypatch.chdir(tmp_path)
        # Load via relative path with spaces
        rel_path = "policies with spaces/custom rules.json"
        rules = load_policy_rules(rel_path)
        assert len(rules) == 1
        assert rules[0].id == "deny-spaces"


# ---------------------------------------------------------------------------
# Invalid configuration tests
# ---------------------------------------------------------------------------


class TestInvalidPolicyConfiguration:
    """Tests rejecting malformed or invalid policy configurations."""

    @pytest.mark.parametrize("spec", ["", "   ", "\t\n\r"])
    def test_empty_or_whitespace_spec(self, spec: str) -> None:
        with pytest.raises(PolicyConfigurationError, match="must not be empty or whitespace"):
            load_policy_rules(spec)

    @pytest.mark.parametrize("spec", [None, 123, True, ["default"]])
    def test_non_string_spec(self, spec: any) -> None:
        with pytest.raises(PolicyConfigurationError, match="must be a string"):
            load_policy_rules(spec)  # type: ignore[arg-type]

    def test_missing_custom_file(self, tmp_path: Path) -> None:
        missing_file = tmp_path / "does_not_exist.json"
        with pytest.raises(PolicyConfigurationError, match="Policy file not found"):
            load_policy_rules(str(missing_file))

    def test_directory_as_policy_path(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyConfigurationError, match="Policy path is not a file"):
            load_policy_rules(str(tmp_path))

    def test_invalid_json_syntax(self, tmp_path: Path) -> None:
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{ unclosed: true, ", encoding="utf-8")
        with pytest.raises(PolicyConfigurationError, match="Invalid JSON"):
            load_policy_rules(str(bad_json))

    @pytest.mark.parametrize("root_val", [[], "string", 42, True, False])
    def test_non_object_root(self, root_val: any) -> None:
        with pytest.raises(PolicyConfigurationError, match="must have a JSON object as root"):
            parse_policy_dict(root_val)

    def test_missing_rules_key(self) -> None:
        with pytest.raises(PolicyConfigurationError, match="missing required 'rules' field"):
            parse_policy_dict({})

    @pytest.mark.parametrize("val", [{}, "rules_string", 123, True])
    def test_rules_not_array(self, val: any) -> None:
        with pytest.raises(PolicyConfigurationError, match="must be an array"):
            parse_policy_dict({"rules": val})

    def test_empty_rules_array(self) -> None:
        with pytest.raises(PolicyConfigurationError, match="must not be empty"):
            parse_policy_dict({"rules": []})

    @pytest.mark.parametrize("entry", ["string", 123, True, []])
    def test_rule_entry_not_dict(self, entry: any) -> None:
        with pytest.raises(PolicyConfigurationError, match="must be an object"):
            parse_policy_dict({"rules": [entry]})

    def test_missing_rule_type(self) -> None:
        rule = {"id": "r1", "description": "d1"}
        with pytest.raises(PolicyConfigurationError, match="missing required field 'type'"):
            parse_policy_dict({"rules": [rule]})

    def test_non_string_rule_type(self) -> None:
        rule = {"type": 123, "id": "r1", "description": "d1"}
        with pytest.raises(PolicyConfigurationError, match="field 'type' must be a string"):
            parse_policy_dict({"rules": [rule]})

    def test_unsupported_rule_type(self) -> None:
        rule = {"type": "unknown_type", "id": "r1", "description": "d1"}
        with pytest.raises(PolicyConfigurationError, match="unsupported type 'unknown_type'"):
            parse_policy_dict({"rules": [rule]})

    def test_missing_rule_id(self) -> None:
        rule = {"type": "tool_name", "description": "d1", "tool_name": "sh"}
        with pytest.raises(PolicyConfigurationError, match="missing required field 'id'"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_id", ["", "   ", "\t"])
    def test_empty_rule_id(self, bad_id: str) -> None:
        rule = {"type": "tool_name", "id": bad_id, "description": "d1", "tool_name": "sh"}
        with pytest.raises(PolicyConfigurationError, match="must not be empty or whitespace"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_id", [123, True, False, []])
    def test_non_string_rule_id(self, bad_id: any) -> None:
        rule = {"type": "tool_name", "id": bad_id, "description": "d1", "tool_name": "sh"}
        with pytest.raises(PolicyConfigurationError, match="must be a string"):
            parse_policy_dict({"rules": [rule]})

    def test_duplicate_rule_id(self) -> None:
        doc = {
            "rules": [
                {"type": "tool_name", "id": "dup", "description": "d1", "tool_name": "sh"},
                {"type": "tool_name", "id": "dup", "description": "d2", "tool_name": "bash"},
            ]
        }
        with pytest.raises(PolicyConfigurationError, match="Duplicate rule ID 'dup'"):
            parse_policy_dict(doc)

    def test_missing_description(self) -> None:
        rule = {"type": "tool_name", "id": "r1", "tool_name": "sh"}
        with pytest.raises(PolicyConfigurationError, match="missing required field 'description'"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_desc", ["", "   "])
    def test_empty_description(self, bad_desc: str) -> None:
        rule = {"type": "tool_name", "id": "r1", "description": bad_desc, "tool_name": "sh"}
        with pytest.raises(PolicyConfigurationError, match="must not be empty or whitespace"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_desc", [123, True, {}])
    def test_non_string_description(self, bad_desc: any) -> None:
        rule = {"type": "tool_name", "id": "r1", "description": bad_desc, "tool_name": "sh"}
        with pytest.raises(PolicyConfigurationError, match="must be a string"):
            parse_policy_dict({"rules": [rule]})

    def test_unknown_rule_fields(self) -> None:
        rule = {
            "type": "tool_name",
            "id": "r1",
            "description": "d1",
            "tool_name": "sh",
            "misspelled_action": "DENY",
        }
        with pytest.raises(PolicyConfigurationError, match="unknown field\\(s\\): misspelled_action"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_priority", [True, False, 1.5, "100", []])
    def test_invalid_priority(self, bad_priority: any) -> None:
        rule = {
            "type": "tool_name",
            "id": "r1",
            "description": "d1",
            "tool_name": "sh",
            "priority": bad_priority,
        }
        with pytest.raises(PolicyConfigurationError, match="priority must be an integer"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_action", ["FORBIDDEN", "SKIP", 123, True])
    def test_invalid_action(self, bad_action: any) -> None:
        rule = {
            "type": "tool_name",
            "id": "r1",
            "description": "d1",
            "tool_name": "sh",
            "action": bad_action,
        }
        with pytest.raises(PolicyConfigurationError, match="(invalid action|action must be a string)"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_risk", ["EXTREME", "INFO", 99, False])
    def test_invalid_risk_level(self, bad_risk: any) -> None:
        rule = {
            "type": "tool_name",
            "id": "r1",
            "description": "d1",
            "tool_name": "sh",
            "risk_level": bad_risk,
        }
        with pytest.raises(PolicyConfigurationError, match="(invalid risk_level|risk_level must be a string)"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("conflicting_action", ["DENY", "ALLOW"])
    def test_approval_rule_incompatible_action(self, conflicting_action: str) -> None:
        rule = {
            "type": "approval",
            "id": "r1",
            "description": "d1",
            "tool_name": "sh",
            "action": conflicting_action,
        }
        with pytest.raises(PolicyConfigurationError, match="incompatible action"):
            parse_policy_dict({"rules": [rule]})

    def test_tool_name_rule_missing_tool_name(self) -> None:
        rule = {"type": "tool_name", "id": "r1", "description": "d1"}
        with pytest.raises(PolicyConfigurationError, match="missing required field 'tool_name'"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_tool", ["", "   ", 123, True])
    def test_tool_name_rule_invalid_tool_name(self, bad_tool: any) -> None:
        rule = {"type": "tool_name", "id": "r1", "description": "d1", "tool_name": bad_tool}
        with pytest.raises(PolicyConfigurationError, match="(must be a string|must not be empty)"):
            parse_policy_dict({"rules": [rule]})

    def test_argument_pattern_missing_argument(self) -> None:
        rule = {"type": "argument_pattern", "id": "r1", "description": "d1", "pattern": "foo"}
        with pytest.raises(PolicyConfigurationError, match="missing required field 'argument'"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_arg", ["", "   ", 123, False])
    def test_argument_pattern_invalid_argument(self, bad_arg: any) -> None:
        rule = {
            "type": "argument_pattern",
            "id": "r1",
            "description": "d1",
            "argument": bad_arg,
            "pattern": "foo",
        }
        with pytest.raises(PolicyConfigurationError, match="(must be a string|must not be empty)"):
            parse_policy_dict({"rules": [rule]})

    def test_argument_pattern_missing_pattern(self) -> None:
        rule = {"type": "argument_pattern", "id": "r1", "description": "d1", "argument": "path"}
        with pytest.raises(PolicyConfigurationError, match="missing required field 'pattern'"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_pattern", ["", 123, True])
    def test_argument_pattern_invalid_pattern(self, bad_pattern: any) -> None:
        rule = {
            "type": "argument_pattern",
            "id": "r1",
            "description": "d1",
            "argument": "path",
            "pattern": bad_pattern,
        }
        with pytest.raises(PolicyConfigurationError, match="(must be a string|must not be empty)"):
            parse_policy_dict({"rules": [rule]})

    @pytest.mark.parametrize("bad_regex_val", ["true", 1, 0, []])
    def test_argument_pattern_invalid_is_regex_type(self, bad_regex_val: any) -> None:
        rule = {
            "type": "argument_pattern",
            "id": "r1",
            "description": "d1",
            "argument": "path",
            "pattern": "foo",
            "is_regex": bad_regex_val,
        }
        with pytest.raises(PolicyConfigurationError, match="field 'is_regex' must be a boolean"):
            parse_policy_dict({"rules": [rule]})

    def test_argument_pattern_invalid_regex_syntax(self) -> None:
        rule = {
            "type": "argument_pattern",
            "id": "r1",
            "description": "d1",
            "argument": "path",
            "pattern": "[unclosed_regex",
            "is_regex": True,
        }
        with pytest.raises(PolicyConfigurationError, match="invalid regular expression"):
            parse_policy_dict({"rules": [rule]})

    def test_approval_missing_tool_name(self) -> None:
        rule = {"type": "approval", "id": "r1", "description": "d1"}
        with pytest.raises(PolicyConfigurationError, match="missing required field 'tool_name'"):
            parse_policy_dict({"rules": [rule]})

    def test_file_read_os_error(self, tmp_path: Path) -> None:
        file_path = tmp_path / "locked.json"
        file_path.write_text("{}", encoding="utf-8")
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with pytest.raises(PolicyConfigurationError, match="Cannot read policy file"):
                load_policy_rules(str(file_path))


# ---------------------------------------------------------------------------
# CLI and GatewayConfig integration tests
# ---------------------------------------------------------------------------


class TestGatewayCLIIntegration:
    """End-to-end tests for CLI configuration and gateway command integration."""

    def test_load_config_default_policies(self, tmp_path: Path) -> None:
        config_file = tmp_path / "gateway_config.json"
        config_file.write_text(
            json.dumps({"upstream": "python -m dummy_server", "policies": "default"}),
            encoding="utf-8",
        )
        cfg = load_config(path=str(config_file))
        assert cfg.upstream_command == "python"
        assert cfg.upstream_args == ["-m", "dummy_server"]
        assert cfg.policies == "default"

    def test_load_config_custom_policies(self, tmp_path: Path) -> None:
        config_file = tmp_path / "gateway_config.json"
        config_file.write_text(
            json.dumps({"upstream": "python -m dummy_server", "policies": "custom_rules.json"}),
            encoding="utf-8",
        )
        cfg = load_config(path=str(config_file))
        assert cfg.policies == "custom_rules.json"

    def test_load_config_upstream_cli_override(self, tmp_path: Path) -> None:
        config_file = tmp_path / "gateway_config.json"
        config_file.write_text(
            json.dumps({"upstream": "python -m file_server", "policies": "custom_rules.json"}),
            encoding="utf-8",
        )
        cfg = load_config(path=str(config_file), cli_upstream="node server.js")
        assert cfg.upstream_command == "node"
        assert cfg.upstream_args == ["server.js"]
        assert cfg.policies == "custom_rules.json"

    def test_cli_gateway_with_default_policies(self, capsys: pytest.CaptureFixture[str]) -> None:
        args = argparse.Namespace(config=None, upstream="python -m dummy")

        with patch("agentguard.gateway.server.run_gateway", new_callable=AsyncMock) as mock_run:
            exit_code = run_gateway_command(args)
            assert exit_code == 0
            mock_run.assert_called_once()
            called_config, called_engine, called_store = mock_run.call_args[0]
            assert called_config.policies == "default"
            # Engine has default rules loaded
            assert len(called_engine.rules) == len(DEFAULT_RULES)

    def test_cli_gateway_with_custom_policy_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        policy_file = tmp_path / "custom.json"
        policy_file.write_text(
            json.dumps({
                "rules": [
                    {
                        "type": "tool_name",
                        "id": "deny-custom",
                        "description": "Custom block",
                        "tool_name": "custom_tool",
                    }
                ]
            }),
            encoding="utf-8",
        )

        config_file = tmp_path / "gateway.json"
        config_file.write_text(
            json.dumps({
                "upstream": "python -m upstream_server",
                "policies": str(policy_file),
            }),
            encoding="utf-8",
        )

        args = argparse.Namespace(config=str(config_file), upstream=None)

        with patch("agentguard.gateway.server.run_gateway", new_callable=AsyncMock) as mock_run:
            exit_code = run_gateway_command(args)
            assert exit_code == 0
            mock_run.assert_called_once()
            _, called_engine, _ = mock_run.call_args[0]
            assert len(called_engine.rules) == 1
            assert called_engine.rules[0].id == "deny-custom"
            assert called_engine.evaluate(ToolRequest(tool_name="custom_tool")).action == PolicyAction.DENY

    def test_cli_gateway_with_missing_policy_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file = tmp_path / "gateway.json"
        config_file.write_text(
            json.dumps({
                "upstream": "python -m upstream_server",
                "policies": str(tmp_path / "nonexistent_policy.json"),
            }),
            encoding="utf-8",
        )

        args = argparse.Namespace(config=str(config_file), upstream=None)

        with patch("agentguard.gateway.server.run_gateway", new_callable=AsyncMock) as mock_run:
            exit_code = run_gateway_command(args)
            assert exit_code == 1
            mock_run.assert_not_called()
            captured = capsys.readouterr()
            assert "Error loading policy:" in captured.err
            assert "Policy file not found" in captured.err

    def test_cli_gateway_with_invalid_policy_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad_policy = tmp_path / "bad_policy.json"
        bad_policy.write_text("not json at all", encoding="utf-8")

        config_file = tmp_path / "gateway.json"
        config_file.write_text(
            json.dumps({
                "upstream": "python -m upstream_server",
                "policies": str(bad_policy),
            }),
            encoding="utf-8",
        )

        args = argparse.Namespace(config=str(config_file), upstream=None)

        with patch("agentguard.gateway.server.run_gateway", new_callable=AsyncMock) as mock_run:
            exit_code = run_gateway_command(args)
            assert exit_code == 1
            mock_run.assert_not_called()
            captured = capsys.readouterr()
            assert "Error loading policy:" in captured.err
            assert "Invalid JSON" in captured.err

    def test_cli_gateway_with_missing_config_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        args = argparse.Namespace(config=str(tmp_path / "missing_config.json"), upstream=None)

        with patch("agentguard.gateway.server.run_gateway", new_callable=AsyncMock) as mock_run:
            exit_code = run_gateway_command(args)
            assert exit_code == 1
            mock_run.assert_not_called()
            captured = capsys.readouterr()
            assert "Error loading config:" in captured.err
            assert "Configuration file not found" in captured.err
