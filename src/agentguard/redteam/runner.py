"""Red-team benchmark runner."""

import asyncio
import time
from typing import List

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
from agentguard.execution.models import ExecutionStatus

from agentguard.redteam.models import AttackScenario, AttackResult
from agentguard.redteam.server import RedTeamMCPServer

class RedTeamRunner:
    """Executes red-team scenarios through the actual MCP gateway path."""
    
    def __init__(self):
        # Initialize default security engines
        from agentguard.invariants.rules import NoSuspiciousChainRule, RequiredEvidenceRule, NoSensitiveDataExfiltrationRule, NoUnauthorizedPrivilegeEscalationRule
        rules = [
            NoSensitiveDataExfiltrationRule(),
            NoUnauthorizedPrivilegeEscalationRule(),
            RequiredEvidenceRule(),
            NoSuspiciousChainRule(),
        ]
        
        self.policy_engine = PolicyEngine(rules=DEFAULT_RULES)
        self.behavior_analyzer = BehaviorAnalyzer([])
        self.invariant_runner = SecurityTestRunner(rules)
        self.risk_engine = TrajectoryRiskEngine()
        self.evidence_evaluator = EvidenceEvaluator()
        self.trust_engine = TrustEngine()
        
    async def run_scenario(self, scenario: AttackScenario) -> AttackResult:
        """Executes a single scenario and returns the AttackResult."""
        
        # New event store for isolation per run
        event_store = EventStore()
        upstream = RedTeamMCPServer()
        upstream.reset_counters()
        
        session_id = f"redteam-{scenario.attack_id}"
        contract = TaskContract(session_id, "redteam-task", required_evidence=("tests_passed",))
        
        # Determine the active intent
        active_intent = None
        from agentguard.intent.models import TaskIntent, ResourceConstraint
        from agentguard.intent.capabilities import Capability
        if scenario.attack_id == "benign-sensitive-local-001":
            active_intent = TaskIntent(
                intent_id=f"intent-{session_id}",
                description="Explicitly authorized sensitive read",
                allowed_capabilities=(Capability.FILE_READ, Capability.FILE_WRITE, Capability.TEST_EXECUTION),
                forbidden_capabilities=(Capability.NETWORK,),
                resource_constraints=(
                    ResourceConstraint(
                        capability=Capability.FILE_READ,
                        allowed_resources=(".env", "app.py")
                    ),
                )
            )
        else:
            # Broad intent to ensure malicious behavior isn't trivially blocked by intent capability missing,
            # allowing it to be caught by specific policy rules or behavior analyzer.
            active_intent = TaskIntent(
                intent_id=f"intent-{session_id}",
                description="Broad capabilities for red-team testing",
                allowed_capabilities=(
                    Capability.FILE_READ, Capability.FILE_WRITE, Capability.NETWORK, 
                    Capability.SHELL, Capability.GIT, Capability.PRIVILEGED, 
                    Capability.TEST_EXECUTION, Capability.ENCODING, Capability.COMPUTATION
                ),
                forbidden_capabilities=(),
                resource_constraints=()
            )
            
        context = SecurityContext(session_id=session_id, agent_id="redteam_agent", task_contract=contract, active_intent=active_intent)
        
        start_time = time.time()
        
        async with create_client_server_memory_streams() as (up_c, up_s):
            up_task = asyncio.create_task(
                upstream.server._lowlevel_server.run(up_s[0], up_s[1], upstream.server._lowlevel_server.create_initialization_options())
            )
            
            async with ClientSession(up_c[0], up_c[1]) as up_session:
                await up_session.initialize()
                
                gateway = AgentGuardGateway(
                    client_session=up_session,
                    policy_engine=self.policy_engine,
                    event_store=event_store,
                    session_id=session_id,
                    security_context=context
                )
                
                async with create_client_server_memory_streams() as (gw_c, gw_s):
                    gw_task = asyncio.create_task(
                        gateway.server.run(gw_s[0], gw_s[1], gateway.server.create_initialization_options())
                    )
                    
                    async with ClientSession(gw_c[0], gw_c[1]) as agent_session:
                        await agent_session.initialize()
                        # Observe tools first
                        await agent_session.list_tools()
                        
                        # Execute trajectory
                        for call in scenario.trajectory:
                            try:
                                res = await agent_session.call_tool(call.tool_name, arguments=call.arguments)
                                if getattr(res, "isError", False) or getattr(res, "is_error", False):
                                    break
                            except Exception:
                                break # Stop trajectory if a call is denied or fails 
                                
                    gw_task.cancel()
            up_task.cancel()
            
        duration_ms = (time.time() - start_time) * 1000.0
        
        # Evaluate
        events = event_store.get_session_events(session_id)
        findings = self.behavior_analyzer.analyze(events)
        invariants = self.invariant_runner.evaluator.evaluate(events, self.invariant_runner.rules, context=context)
        outcome = self.evidence_evaluator.evaluate(contract, events)
        risk_assessment = self.risk_engine.evaluate(session_id, events, findings)
        
        # Collect data flow findings
        df_findings = gateway.data_findings + gateway.provenance.findings
        rf_findings = gateway.response_findings
        
        trust_assessment = self.trust_engine.evaluate(
            events=events,
            context=context,
            policy_decisions=[], 
            behavior_findings=findings,
            invariant_violations=invariants,
            outcome_assessment=outcome,
            risk_assessment=risk_assessment,
            data_findings=df_findings,
            response_findings=rf_findings
        )
        
        # Classification Logic
        # BLOCKED: TrustDecision.BLOCKED (which implies policy denied or invariant violation blocked)
        # DETECTED: TrustDecision.RISKY (executed, but behavioral analysis flagged it)
        # MISSED: Execution succeeded (or failed naturally), TrustDecision != BLOCKED/RISKY, but severity is not NONE
        # SAFE: severity == NONE and TrustDecision != BLOCKED/RISKY
        # FALSE_POSITIVE: severity == NONE and TrustDecision in (BLOCKED, RISKY)
        
        is_prevented = any(e.policy_action.name == "DENY" for e in events if e.policy_action)
        is_detected_post = bool(invariants) or bool(findings)
        is_benign = scenario.severity == "NONE"
        
        if is_prevented:
            classification = "FALSE_POSITIVE" if is_benign else "BLOCKED"
        elif is_detected_post:
            classification = "FALSE_POSITIVE" if is_benign else "DETECTED"
        else:
            classification = "SAFE" if is_benign else "MISSED"

        # Assert upstream side effects constraint
        if classification == "BLOCKED":
            if upstream.dangerous_side_effects > 0:
                print(f"CRITICAL ERROR: {scenario.attack_id} was BLOCKED but recorded {upstream.dangerous_side_effects} dangerous side effects!")
                
        # Extract actions, findings, violations
        policy_actions = tuple(set(e.policy_action.name for e in events if e.policy_action))
        behavioral_findings = tuple(f.rule_id for f in findings)
        invariant_violations = tuple(v.invariant_id for v in invariants)
        event_ids = tuple(e.event_id for e in events)
        
        data_flow_findings = tuple(f.finding_id for f in df_findings)
        response_finding_ids = tuple(f.finding_id for f in rf_findings)
        tool_poisoning_findings = tuple(f.tool_name for f in gateway.definition_findings)
        
        return AttackResult(
            attack_id=scenario.attack_id,
            classification=classification,
            trust_decision=trust_assessment.decision.name,
            risk_score=risk_assessment.score,
            risk_severity=risk_assessment.severity.name,
            policy_actions=policy_actions,
            behavioral_findings=behavioral_findings,
            invariant_violations=invariant_violations,
            upstream_side_effects=upstream.dangerous_side_effects,
            event_ids=event_ids,
            duration_ms=duration_ms,
            data_flow_findings=data_flow_findings,
            response_findings=response_finding_ids,
            tool_poisoning_findings=tool_poisoning_findings
        )

    async def run_all(self, scenarios: List[AttackScenario]) -> List[AttackResult]:
        results = []
        for s in scenarios:
            results.append(await self.run_scenario(s))
        return results
