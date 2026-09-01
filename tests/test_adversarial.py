import pytest
from agentguard.redteam.adversarial import AdversarialGenerator, AdversarialRunner, AdversarialReport, AdversarialTestCase

def test_adversarial_generator():
    generator = AdversarialGenerator()
    cases = generator.generate()
    
    assert len(cases) > 0
    
    families = set(c.family for c in cases)
    assert "FILESYSTEM_PATH_BYPASS" in families
    assert "NETWORK_SSRF_BYPASS" in families
    assert "CAPABILITY_BYPASS" in families
    assert "MCP_TOOL_SECURITY" in families
    
    # Check determinism
    generator2 = AdversarialGenerator()
    cases2 = generator2.generate()
    assert len(cases) == len(cases2)
    assert cases[0].test_id == cases2[0].test_id
    assert cases[0].arguments == cases2[0].arguments

def test_adversarial_runner():
    import asyncio
    runner = AdversarialRunner()
    
    # A safe case that SHOULD bypass (for the sake of unit testing the runner itself,
    # though in the actual benchmark all generated cases are malicious)
    safe_case = AdversarialTestCase(
        test_id="safe-1",
        family="SAFE",
        tool_name="read_file",
        arguments={"path": "/app/workspace/safe.txt"},
        description="Safe read"
    )
    
    # A malicious case that should be blocked
    bad_case = AdversarialTestCase(
        test_id="bad-1",
        family="FILESYSTEM_PATH_BYPASS",
        tool_name="read_file",
        arguments={"path": "../.env"},
        description="Traversal"
    )
    
    report = asyncio.run(runner.run_all([safe_case, bad_case]))
    
    assert report.total_cases == 2
    assert report.blocked == 1
    assert report.missed == 1
    assert report.bypass_rate == 50.0
    
    dict_rep = report.to_dict()
    assert dict_rep["blocked"] == 1
    assert dict_rep["missed"] == 1
    
    text_rep = report.to_text()
    assert "Blocked:     1" in text_rep
    assert "Missed:      1" in text_rep
