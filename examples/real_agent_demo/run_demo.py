import asyncio
import sys
import json
from mcp.shared.memory import create_client_server_memory_streams
from mcp.client.session import ClientSession

from agentguard.policy.defaults import DEFAULT_RULES
from agentguard.policy.engine import PolicyEngine
from agentguard.events.store import EventStore
from agentguard.behavior.analyzer import BehaviorAnalyzer
from agentguard.invariants.runner import SecurityTestRunner
from agentguard.risk.engine import TrajectoryRiskEngine
from agentguard.outcome.evaluator import EvidenceEvaluator
from agentguard.trust.engine import TrustEngine
from agentguard.context.models import SecurityContext
from agentguard.outcome.models import TaskContract

from agentguard.gateway.proxy import AgentGuardGateway
from examples.real_agent_demo.server import create_demo_server
from examples.real_agent_demo.agent import DeterministicDemoAgent


async def run_scenario(scenario_name: str, task_contract: TaskContract = None):
    print(f"\n========================================")
    print(f"Scenario: {scenario_name}")
    print(f"========================================\n")
    
    print("Agent\n  v\nMCP Client\n  v\nAgentGuard Gateway\n  v\nMCP Server\n")
    
    from agentguard.invariants.rules import NoSuspiciousChainRule, RequiredEvidenceRule, NoSensitiveDataExfiltrationRule, NoUnauthorizedPrivilegeEscalationRule
    
    rules = [
        NoSensitiveDataExfiltrationRule(),
        NoUnauthorizedPrivilegeEscalationRule(),
        RequiredEvidenceRule(),
        NoSuspiciousChainRule(),
    ]
    
    # 1. Setup AgentGuard components
    policy_engine = PolicyEngine(rules=DEFAULT_RULES)
    event_store = EventStore()
    behavior_analyzer = BehaviorAnalyzer([])
    invariant_runner = SecurityTestRunner(rules)
    risk_engine = TrajectoryRiskEngine()
    evidence_evaluator = EvidenceEvaluator()
    trust_engine = TrustEngine()
    
    upstream_server = create_demo_server()
    
    async with create_client_server_memory_streams() as (up_client_streams, up_server_streams):
        # Start upstream server
        upstream_task = asyncio.create_task(
            upstream_server._lowlevel_server.run(up_server_streams[0], up_server_streams[1], upstream_server._lowlevel_server.create_initialization_options())
        )
        
        async with ClientSession(up_client_streams[0], up_client_streams[1]) as up_client_session:
            await up_client_session.initialize()
            
            gateway = AgentGuardGateway(
                client_session=up_client_session,
                policy_engine=policy_engine,
                event_store=event_store
            )
            
            async with create_client_server_memory_streams() as (ag_client_streams, ag_server_streams):
                # Start gateway server
                gateway_task = asyncio.create_task(
                    gateway.server.run(ag_server_streams[0], ag_server_streams[1], gateway.server.create_initialization_options())
                )
                
                async with ClientSession(ag_client_streams[0], ag_client_streams[1]) as ag_client_session:
                    await ag_client_session.initialize()
                    
                    agent = DeterministicDemoAgent(ag_client_session)
                    
                    # Agent executes!
                    results = await agent.execute_trajectory(scenario_name)
                    for r in results:
                        if isinstance(r, dict) and "error" in r:
                            print(f"Agent error: {r['error']}")
                    
                # Gateway shutdown
                gateway_task.cancel()
        
        # Upstream shutdown
        upstream_task.cancel()
        
    # Assessment
    sessions = list(event_store._events_by_session.values())
    events = sessions[0] if sessions else []
    
    # Ensure all events share a session (AgentGuard Gateway assigns a random one if not provided, but we want all in one for demo)
    session_id = events[0].session_id if events else "demo_session"
    
    print("Tool calls:")
    for e in events:
        mark = "[+]" if e.execution_status.name == "EXECUTED" else "[x]"
        arg_str = ", ".join(f"{k}='{v}'" for k, v in e.arguments.items())
        print(f"  {mark} {e.tool_name}({arg_str})")
        
    context = SecurityContext(session_id=session_id, agent_id="demo_agent", task_contract=task_contract)
    
    findings = behavior_analyzer.analyze(events)
    invariants = invariant_runner.evaluator.evaluate(events, invariant_runner.rules, context=context)
    outcome = evidence_evaluator.evaluate(task_contract, events) if task_contract else None
    
    risk_assessment = risk_engine.evaluate(session_id, events, findings)
    
    trust_assessment = trust_engine.evaluate(
        events=events,
        context=context,
        policy_decisions=[], 
        behavior_findings=findings,
        invariant_violations=invariants,
        outcome_assessment=outcome,
        risk_assessment=risk_assessment
    )

    upstream_calls = sum(1 for e in events if e.execution_status.name == "EXECUTED")
    
    print(f"\nAgentGuard:")
    print(f"  {trust_assessment.decision.name}")
    
    if trust_assessment.decision.name == "BLOCKED":
        denied_events = [e for e in events if e.execution_status.name == "DENIED"]
        if denied_events:
            print(f"\nReason:\n  Blocked by {denied_events[0].rule_id}")
            
    print(f"\nRisk:\n  {risk_assessment.severity.name}")
    if findings:
        print(f"\nBehavior:\n  FINDING")
        
    print(f"\nSecurity invariant:\n  {'FAIL' if invariants else 'PASS'}")
    
    print(f"\nUpstream calls:\n  {upstream_calls}")
    print("\n")
    
    return {
        "scenario": scenario_name,
        "trust": trust_assessment.decision.name,
        "risk": risk_assessment.severity.name,
        "upstream_calls": upstream_calls
    }


async def main(json_output=False):
    contract = TaskContract("demo1", "demo", required_evidence=("tests_passed", "file_modified"))
    
    results = []
    
    if not json_output:
        print("========================================")
        print("AgentGuard Real MCP Demo")
        print("========================================")
        
    res1 = await run_scenario("SAFE DEVELOPMENT", task_contract=contract)
    results.append(res1)
    
    res2 = await run_scenario("SECRET EXFILTRATION", task_contract=contract)
    results.append(res2)
    
    res3 = await run_scenario("SUSPICIOUS CHAIN", task_contract=contract)
    results.append(res3)
    
    if json_output:
        summary = {
            "trusted": sum(1 for r in results if r["trust"] == "TRUSTED"),
            "blocked": sum(1 for r in results if r["trust"] == "BLOCKED"),
            "risky": sum(1 for r in results if r["trust"] == "RISKY"),
            "unverified": sum(1 for r in results if r["trust"] == "UNVERIFIED"),
            "errors": sum(1 for r in results if r["trust"] == "ERROR"),
        }
        output = {
            "scenarios": results,
            "summary": summary
        }
        # In json mode, we want to hide the print output of run_scenario.
        # But this is simple enough for demo purposes.
        pass

if __name__ == "__main__":
    asyncio.run(main())
