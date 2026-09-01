import pytest
import json
import subprocess
from unittest.mock import patch, MagicMock

from agentguard.cli import run_security_gate_command

@pytest.fixture
def mock_all():
    from unittest.mock import AsyncMock
    with patch("subprocess.run") as mock_run, \
         patch("agentguard.redteam.adversarial.AdversarialRunner.run_all", new_callable=AsyncMock) as mock_adv, \
         patch("agentguard.redteam.attacks.load_v1_scenarios") as mock_rt_scen, \
         patch("agentguard.redteam.runner.RedTeamRunner.run_all", new_callable=AsyncMock) as mock_rt_run, \
         patch("agentguard.audit.tamper.AuditTamperRunner.run_scenario") as mock_audit:
         
        mock_run.return_value = MagicMock(returncode=0)
        
        adv_report = MagicMock()
        adv_report.missed = 0
        adv_report.bypass_rate = 0.0
        mock_adv.return_value = adv_report

        rt_report_results = [] 
        mock_rt_run.return_value = rt_report_results
        mock_rt_scen.return_value = []
        
        with patch("agentguard.redteam.report.RedTeamReport") as mock_rt_report_cls:
            mock_rt_report = MagicMock()
            mock_rt_report.metrics.critical_misses = []
            mock_rt_report.metrics.false_positives = 0
            mock_rt_report.metrics.dangerous_upstream_side_effects = 0
            mock_rt_report_cls.return_value = mock_rt_report
            
            with patch("agentguard.audit.tamper.get_tamper_scenarios") as mock_get_audit:
                mock_get_audit.return_value = [MagicMock()]
                mock_audit.return_value = MagicMock(detected=True)
            
                yield {
                    "subprocess": mock_run,
                    "adv_report": adv_report,
                    "rt_report": mock_rt_report,
                    "audit": mock_audit
                }



def test_gate_pass(mock_all, capsys):
    """Test that the gate passes when all checks are green."""
    res = run_security_gate_command(json_output=False)
    assert res == 0
    captured = capsys.readouterr().out
    assert "SECURITY GATE: PASS" in captured

def test_gate_pass_json(mock_all, capsys):
    """Test JSON output on pass."""
    res = run_security_gate_command(json_output=True)
    assert res == 0
    data = json.loads(capsys.readouterr().out)
    assert data["gate_passed"] is True
    assert data["results"]["unit_tests"]["pass"] is True
    assert data["results"]["adversarial"]["pass"] is True
    assert data["results"]["red_team_prevention"]["pass"] is True
    assert data["results"]["red_team_detection"]["pass"] is True
    assert data["results"]["audit_integrity"]["pass"] is True

def test_gate_pytest_fail(mock_all, capsys):
    """Test that the gate fails when unit tests fail."""
    mock_all["subprocess"].return_value = MagicMock(returncode=1)
    res = run_security_gate_command(json_output=False)
    assert res == 1
    captured = capsys.readouterr().out
    assert "Unit Tests                FAIL" in captured
    assert "SECURITY GATE: FAIL" in captured

def test_gate_adversarial_bypass(mock_all, capsys):
    """Test that the gate fails when adversarial tests have bypass."""
    mock_all["adv_report"].missed = 1
    mock_all["adv_report"].bypass_rate = 1.5
    res = run_security_gate_command(json_output=False)
    assert res == 1
    captured = capsys.readouterr().out
    assert "Adversarial Authorization FAIL" in captured
    assert "SECURITY GATE: FAIL" in captured

def test_gate_redteam_critical_miss(mock_all, capsys):
    """Test that the gate fails when red-team has critical misses."""
    mock_all["rt_report"].metrics.critical_misses = ["mock-scenario-1"]
    res = run_security_gate_command(json_output=False)
    assert res == 1
    captured = capsys.readouterr().out
    assert "Red-Team Detection        FAIL" in captured
    assert "Critical Misses           1" in captured
    assert "SECURITY GATE: FAIL" in captured

def test_gate_redteam_side_effects(mock_all, capsys):
    """Test that the gate fails when red-team has dangerous upstream side effects."""
    mock_all["rt_report"].metrics.dangerous_upstream_side_effects = 1
    res = run_security_gate_command(json_output=False)
    assert res == 1
    captured = capsys.readouterr().out
    assert "Red-Team Prevention       FAIL" in captured
    assert "Dangerous Side Effects    1" in captured
    assert "SECURITY GATE: FAIL" in captured

def test_gate_redteam_false_positives(mock_all, capsys):
    """Test that the gate fails when red-team has false positives."""
    mock_all["rt_report"].metrics.false_positives = 1
    res = run_security_gate_command(json_output=False)
    assert res == 1
    captured = capsys.readouterr().out
    assert "Red-Team Detection        FAIL" in captured
    assert "False Positives           1" in captured
    assert "SECURITY GATE: FAIL" in captured

def test_gate_audit_tamper_fail(mock_all, capsys):
    """Test that the gate fails when audit tamper tests fail to detect an attack."""
    mock_all["audit"].return_value = MagicMock(detected=False)
    res = run_security_gate_command(json_output=False)
    assert res == 1
    captured = capsys.readouterr().out
    assert "Audit Integrity           FAIL" in captured
    assert "SECURITY GATE: FAIL" in captured
