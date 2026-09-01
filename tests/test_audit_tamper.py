import json
import pytest
import os
from unittest.mock import patch, MagicMock
from io import StringIO
from datetime import datetime, timezone

from agentguard.audit.tamper import (
    AuditTamperRunner,
    get_tamper_scenarios,
    AuditIsolationPolicy
)
from agentguard.audit.repository import AuditRepository
from agentguard.audit.database import AuditPersistenceError
from agentguard.events.models import ToolEvent
from agentguard.events.store import EventStore
from agentguard.policy.models import PolicyAction, RiskLevel
from agentguard.execution.models import ExecutionStatus
from agentguard.cli import main

def test_tamper_runner_all_scenarios():
    runner = AuditTamperRunner()
    scenarios = get_tamper_scenarios()
    
    assert len(scenarios) == 10
    
    for scenario in scenarios:
        result = runner.run_scenario(scenario)
        # All of our scenarios are designed to be detectable
        assert result.detected is True, f"Failed to detect tampering for {scenario.attack_type}"
        assert result.integrity_valid is False
        assert result.first_invalid_event_id is not None
        assert "prevented" not in str(result.detected)
        
        # Test that raw secrets and raw arguments are not leaked
        assert result.reason is not None
        assert "my_secret" not in result.reason
        assert "arg1" not in result.reason or "<str" in result.reason

def test_isolation_policy_semantics():
    policy = AuditIsolationPolicy()
    assert policy.agent_can_append is True
    assert policy.agent_can_modify is False
    assert policy.agent_can_delete is False
    assert policy.agent_can_verify is True
    assert policy.agent_can_read_raw_storage is False

def test_persistence_failure_fallback():
    # Prove that if audit repository becomes unavailable, security enforcement still works
    mock_repo = MagicMock(spec=AuditRepository)
    mock_repo.append.side_effect = AuditPersistenceError("Disk full")
    
    # Normally ToolExecutor or EventStore is used. Let's test EventStore directly.
    store = EventStore(audit_repository=mock_repo)
    
    # Create a mock tool event that was just evaluated
    event = ToolEvent(
        event_id="e1",
        timestamp=datetime.now(timezone.utc),
        session_id="s1",
        agent_id="a1",
        tool_name="read_file",
        arguments={"path": ".env"},
        policy_action=PolicyAction.DENY,
        risk_level=RiskLevel.CRITICAL,
        execution_status=ExecutionStatus.DENIED,
        rule_id="no-secret-exfiltration"
    )
    
    # This should NOT raise an exception, proving isolation.
    store.record(event)
    
    # Event should be stored in memory successfully
    assert store.get("e1") == event
    assert store.count("s1") == 1
    
    # AuditRepository.append should have been called and failed silently
    assert mock_repo.append.called

def test_cli_attack_text():
    with patch("sys.stdout", new=StringIO()) as out, \
         patch("sys.stderr", new=StringIO()) as err:
        try:
            exit_code = main(["audit", "attack"])
        except SystemExit as e:
            exit_code = e.code
            
        assert exit_code == 0
        output = out.getvalue()
        assert "AgentGuard Audit Tamper Benchmark" in output
        assert "10 / 10 attacks detected" in output
        assert "Integrity benchmark: PASS" in output
        assert "MODIFY_EVENT" in output
        assert "DETECTED" in output

def test_cli_attack_json():
    with patch("sys.stdout", new=StringIO()) as out, \
         patch("sys.stderr", new=StringIO()) as err:
        try:
            exit_code = main(["audit", "attack", "--json"])
        except SystemExit as e:
            exit_code = e.code
            
        assert exit_code == 0
        output = out.getvalue()
        
        data = json.loads(output)
        assert data["benchmark_passed"] is True
        assert data["total_attacks"] == 10
        assert data["detected_attacks"] == 10
        
        for res in data["results"]:
            assert res["detected"] is True
            assert res["tampering_prevented"] is False
            assert res["tampering_detected"] is True
            assert "scenario_id" in res
            assert "attack_type" in res
