import time
import uuid
import logging
from datetime import datetime, timezone

from mcp.server import Server
import mcp.types as types
from mcp.client.session import ClientSession

from agentguard.policy.engine import PolicyEngine
from agentguard.policy.models import ToolRequest, PolicyAction, PolicyDecision, RiskLevel
from agentguard.execution.models import ExecutionStatus
from agentguard.events.models import ToolEvent
from agentguard.dataflow.provenance import ProvenanceTracker
from agentguard.dataflow.inspector import (
    ToolArgumentInspector, ToolResponseInspector, ToolDefinitionInspector
)

from agentguard.dataflow.models import DataClassification
from agentguard.context.models import SecurityContext
from agentguard.intent.enforcement import IntentEnforcer
from agentguard.integrity.registry import ToolRegistry
from agentguard.integrity.findings import IntegrityFindingType

logger = logging.getLogger(__name__)

class AgentGuardGateway:
    """Acts as a proxy between an MCP client and an upstream MCP server, enforcing AgentGuard policies."""

    def __init__(self, client_session: ClientSession, policy_engine: PolicyEngine, event_store=None, session_id=None, security_context: SecurityContext | None = None):
        self.client_session = client_session
        self.policy_engine = policy_engine
        self.event_store = event_store
        self.session_id = session_id or uuid.uuid4().hex
        self.security_context = security_context
        
        active_intent = self.security_context.active_intent if self.security_context else None
        self.intent_enforcer = IntentEnforcer(intent=active_intent)
        
        self.provenance = ProvenanceTracker()
        self.arg_inspector = ToolArgumentInspector()
        self.resp_inspector = ToolResponseInspector()
        
        self.data_findings = []
        self.response_findings = []
        self.definition_findings = []
        
        self.tool_registry = ToolRegistry()
        
        self.server = Server("AgentGuard MCP Gateway")
        self._setup_handlers()

    def _setup_handlers(self):
        async def handle_list_tools(ctx, params: types.PaginatedRequestParams | None = None) -> types.ListToolsResult:
            """Forwards tools/list to the upstream server, returning original definitions."""
            result = await self.client_session.list_tools()
            if result and hasattr(result, "tools"):
                for t in result.tools:
                    df = ToolDefinitionInspector.inspect(t.name, t.description)
                    if df:
                        self.definition_findings.append(df)
                        
                    # Integrity tracking
                    integrity_findings = self.tool_registry.register_tool(t, "upstream")
                    if integrity_findings:
                        self.definition_findings.extend(integrity_findings)
                        
            return result
        self.server.add_request_handler("tools/list", types.PaginatedRequestParams, handle_list_tools)

        async def handle_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
            """Intercepts tools/call to enforce policies before forwarding."""
            tool_name = params.name
            arguments = params.arguments or {}
            
            # PRE-EXECUTION INTEGRITY CHECK
            try:
                upstream_tools = await self.client_session.list_tools()
                target_tool = None
                if upstream_tools and hasattr(upstream_tools, "tools"):
                    for t in upstream_tools.tools:
                        if t.name == tool_name:
                            target_tool = t
                            break
                            
                if not target_tool:
                    return types.CallToolResult(
                        isError=True,
                        content=[types.TextContent(type="text", text=f"AgentGuard denied execution: Tool '{tool_name}' no longer exists on the upstream server.")]
                    )
                    
                integrity_findings = self.tool_registry.verify_tool(target_tool, "upstream")
                if integrity_findings:
                    self.definition_findings.extend(integrity_findings)
                    for finding in integrity_findings:
                        if finding.type in (IntegrityFindingType.TOOL_RUG_PULL, IntegrityFindingType.UNAPPROVED_NEW_TOOL):
                            return types.CallToolResult(
                                isError=True,
                                content=[types.TextContent(type="text", text=f"AgentGuard denied execution: Integrity violation ({finding.type.value}). Tool definition changed dynamically.")]
                            )
            except Exception as e:
                return types.CallToolResult(
                    isError=True,
                    content=[types.TextContent(type="text", text=f"AgentGuard integrity check failed: {e}")]
                )
                
            tool_request = ToolRequest(tool_name=tool_name, arguments=arguments)
            
            try:
                # 1. Intent Enforcement takes absolute precedence
                intent_decision = self.intent_enforcer.evaluate(tool_request)
                if intent_decision:
                    decision = intent_decision
                else:
                    # 2. Fall back to standard Policy Engine
                    decision = self.policy_engine.evaluate(tool_request)
            except Exception as e:
                # Fail closed on evaluation error
                return types.CallToolResult(
                    isError=True,
                    content=[types.TextContent(type="text", text=f"AgentGuard internal error: {e}")]
                )
            
            start_time = time.monotonic()
            event_id = uuid.uuid4().hex
            session_id = tool_request.session_id if hasattr(tool_request, "session_id") and tool_request.session_id else self.session_id
            
            # PRE-EXECUTION INVARIANT CHECK
            if decision.action != PolicyAction.DENY and self.event_store:
                current_events = self.event_store.get_session_events(session_id)
                if current_events:
                    # Create a temporary dummy event for evaluation
                    dummy_event = ToolEvent(
                        event_id=event_id,
                        timestamp=datetime.now(timezone.utc),
                        session_id=session_id,
                        agent_id="gateway",
                        tool_name=tool_name,
                        arguments=arguments,
                        policy_action=decision.action,
                        risk_level=decision.risk_level,
                        execution_status=ExecutionStatus.EXECUTED,
                        rule_id=decision.rule_id,
                        duration_ms=0,
                        data_classifications=tuple(),
                        finding_ids=tuple()
                    )
                    # We evaluate NoSuspiciousChainRule pre-execution
                    from agentguard.invariants.rules import NoSuspiciousChainRule
                    rule = NoSuspiciousChainRule()
                    violations = rule.evaluate(current_events + [dummy_event])
                    if violations:
                        decision = PolicyDecision(
                            action=PolicyAction.DENY,
                            reason="Pre-execution invariant check: Suspicious execution chain detected.",
                            rule_id="gateway-suspicious-chain-block",
                            risk_level=RiskLevel.CRITICAL
                        )
            
            status = None
            error_msg = None
            result_content = []
            is_error = False
            
            # 1. Inspect arguments pre-execution
            arg_result = self.arg_inspector.inspect(tool_name, arguments, event_id)
            if arg_result.findings:
                self.data_findings.extend(arg_result.findings)
                
            # Track origin for sensitive files
            for cls, fp in zip(arg_result.classifications, arg_result.fingerprints):
                self.provenance.record_origin(fp, event_id, "ARGUMENT", tool_name, cls)
                
            # Track destination data flows
            self.provenance.check_destination(tool_name, arguments, event_id, list(arg_result.fingerprints))
            
            # Data Flow Enforcement: Block immediately if a HIGH or CRITICAL risk is found in arguments/provenance
            # Check the findings we just appended to self.data_findings and self.provenance.findings for this event
            high_risk_findings = [f for f in arg_result.findings if f.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
            high_risk_provenance = [f for f in self.provenance.findings if f.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL) and event_id in f.event_ids]
            
            if high_risk_findings or high_risk_provenance:
                if decision.action != PolicyAction.DENY:
                    decision = PolicyDecision(
                        action=PolicyAction.DENY,
                        reason="Pre-execution data flow analysis detected a sensitive/secret exfiltration or dangerous pattern.",
                        rule_id="gateway-data-flow-block",
                        risk_level=RiskLevel.CRITICAL
                    )
            
            if decision.action == PolicyAction.DENY:
                status = ExecutionStatus.DENIED
                error_msg = f"AgentGuard denied execution: {decision.reason}"
                result_content = [types.TextContent(type="text", text=error_msg)]
                is_error = True
                
            elif decision.action == PolicyAction.REQUIRE_APPROVAL:
                status = ExecutionStatus.APPROVAL_REQUIRED
                error_msg = f"AgentGuard requires approval: {decision.reason}"
                result_content = [types.TextContent(type="text", text=error_msg)]
                is_error = True
                
            else:
                # ALLOW
                try:
                    upstream_result = await self.client_session.call_tool(tool_name, arguments)
                    status = ExecutionStatus.EXECUTED
                    # Extract response content
                    resp_text = ""
                    if hasattr(upstream_result, "content") and upstream_result.content:
                        for c in upstream_result.content:
                            if c.type == "text" and hasattr(c, "text"):
                                resp_text += c.text + "\n"
                                
                    # 2. Inspect response post-execution
                    resp_findings = self.resp_inspector.inspect(tool_name, resp_text, event_id)
                    if resp_findings:
                        self.response_findings.extend(resp_findings)
                        for rf in resp_findings:
                            self.provenance.record_origin(rf.fingerprint, event_id, "RESPONSE", tool_name, DataClassification.SECRET)
                            
                    # 3. Track transformation output if any
                    self.provenance.track_transformation(tool_name, arguments, resp_text, event_id)
                    
                except Exception as e:
                    status = ExecutionStatus.FAILED
                    error_msg = str(e)
                    result_content = [types.TextContent(type="text", text=error_msg)]
                    is_error = True
            
            duration_ms = (time.monotonic() - start_time) * 1000
            
            # Gather IDs
            finding_ids = [f.finding_id for f in arg_result.findings]
            if status == ExecutionStatus.EXECUTED and "resp_findings" in locals():
                finding_ids.extend(f.finding_id for f in resp_findings)
            
            event = ToolEvent(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                session_id=session_id,
                agent_id="gateway",
                tool_name=tool_name,
                arguments=arguments,
                policy_action=decision.action,
                risk_level=decision.risk_level,
                execution_status=status,
                rule_id=decision.rule_id,
                duration_ms=duration_ms,
                data_classifications=tuple(c.name for c in arg_result.classifications),
                finding_ids=tuple(finding_ids)
            )
            
            if self.event_store:
                self.event_store.record(event)
                
            if decision.action == PolicyAction.ALLOW and status == ExecutionStatus.EXECUTED:
                return upstream_result
                
            return types.CallToolResult(
                is_error=is_error,
                content=result_content
            )
        self.server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call_tool)
