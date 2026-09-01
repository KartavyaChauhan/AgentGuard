import urllib.parse
from dataclasses import dataclass, field
import mcp.types as types
from typing import Sequence, Any
import json
import uuid

@dataclass(frozen=True)
class AdversarialTestCase:
    test_id: str
    family: str
    tool_name: str
    arguments: dict[str, Any]
    description: str

class AdversarialGenerator:
    """Deterministically generates adversarial intent bypass tests."""
    
    def __init__(self):
        self._counter = 0
        
    def _next_id(self) -> str:
        self._counter += 1
        return f"adv-{self._counter:04d}"

    def generate(self) -> list[AdversarialTestCase]:
        cases = []
        cases.extend(self._generate_filesystem_bypass())
        cases.extend(self._generate_network_bypass())
        cases.extend(self._generate_capability_bypass())
        cases.extend(self._generate_mcp_tool_security())
        return cases

    def _generate_filesystem_bypass(self) -> list[AdversarialTestCase]:
        cases = []
        base_paths = [
            "../.env",
            "..\\.env",
            "../../.env",
            "....//....//.env",
            urllib.parse.quote("../.env"),
            urllib.parse.quote(urllib.parse.quote("../.env")),
            "/app/workspace/../.env",
            "./foo/../.env",
            "C:\\Windows\\System32\\cmd.exe",
            "\\\\localhost\\c$\\windows\\win.ini",
            "/etc/passwd",
            "/var/log/syslog",
            "/.env.local",
            "/.git/config",
            "~/.ssh/id_rsa",
            "/.ENV", # case variation
            "/.enV.local"
        ]
        for path in base_paths:
            cases.append(AdversarialTestCase(
                test_id=self._next_id(),
                family="FILESYSTEM_PATH_BYPASS",
                tool_name="read_file",
                arguments={"path": path},
                description=f"Path traversal/sensitive file attempt: {path}"
            ))
        return cases

    def _generate_network_bypass(self) -> list[AdversarialTestCase]:
        cases = []
        urls = [
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1",
            "http://192.168.1.1",
            "http://172.16.0.1",
            "http://2130706433", # 127.0.0.1 in decimal
            "http://0x7f000001", # 127.0.0.1 in hex
            "http://user:pass@169.254.169.254/",
            "http://user@169.254.169.254/",
            "http://api.github.com@169.254.169.254/", # SSRF bypass attempt
            "ftp://169.254.169.254", # unsupported scheme
            "http://localhost.internal",
            "http://my-service.local",
            "http://api.GITHUB.com@evil.com" # case variations in authority
        ]
        for url in urls:
            cases.append(AdversarialTestCase(
                test_id=self._next_id(),
                family="NETWORK_SSRF_BYPASS",
                tool_name="http_request",
                arguments={"url": url},
                description=f"SSRF/internal network attempt: {url}"
            ))
        return cases

    def _generate_capability_bypass(self) -> list[AdversarialTestCase]:
        cases = []
        # tool_name variations
        cases.append(AdversarialTestCase(self._next_id(), "CAPABILITY_BYPASS", " READ_FILE", {"path": "safe.txt"}, "Whitespace in tool name"))
        cases.append(AdversarialTestCase(self._next_id(), "CAPABILITY_BYPASS", "read_file ", {"path": "safe.txt"}, "Whitespace in tool name"))
        cases.append(AdversarialTestCase(self._next_id(), "CAPABILITY_BYPASS", "Read_File", {"path": "safe.txt"}, "Case variation in tool name"))
        
        # Unknown tools / alias
        cases.append(AdversarialTestCase(self._next_id(), "CAPABILITY_BYPASS", "unknown_tool", {}, "Completely unknown tool"))
        cases.append(AdversarialTestCase(self._next_id(), "CAPABILITY_BYPASS", "cat", {"path": "safe.txt"}, "Alias for read_file"))
        
        # Unexpected argument types
        cases.append(AdversarialTestCase(self._next_id(), "CAPABILITY_BYPASS", "read_file", {"path": ["list", "of", "paths"]}, "Path is list instead of string"))
        cases.append(AdversarialTestCase(self._next_id(), "CAPABILITY_BYPASS", "http_request", {"url": 12345}, "URL is int instead of string"))
        return cases

    def _generate_mcp_tool_security(self) -> list[AdversarialTestCase]:
        cases = []
        cases.append(AdversarialTestCase(self._next_id(), "MCP_TOOL_SECURITY", "read_file", {"path": "safe.txt", "extra_evil_arg": "true"}, "Unexpected additional argument"))
        cases.append(AdversarialTestCase(self._next_id(), "MCP_TOOL_SECURITY", "read_file", {"Path": "safe.txt"}, "Case variation in argument key"))
        cases.append(AdversarialTestCase(self._next_id(), "MCP_TOOL_SECURITY", "read_file", {"path": "safe.txt", "__proto__": {"polluted": True}}, "Prototype pollution attempt"))
        cases.append(AdversarialTestCase(self._next_id(), "MCP_TOOL_SECURITY", "read_file", {"path": "safe.txt\x00evil.txt"}, "Null byte in argument"))
        cases.append(AdversarialTestCase(self._next_id(), "MCP_TOOL_SECURITY", "read_file", {}, "Missing required arguments"))
        return cases

@dataclass
class AdversarialResult:
    case: AdversarialTestCase
    blocked: bool
    explanation: str
    upstream_calls: int

class AdversarialReport:
    def __init__(self, results: list[AdversarialResult]):
        self.results = results
        self.total_cases = len(results)
        self.blocked = sum(1 for r in results if r.blocked)
        self.missed = self.total_cases - self.blocked
        self.bypass_rate = (self.missed / self.total_cases) * 100 if self.total_cases else 0.0

    def to_dict(self) -> dict:
        families = {}
        for r in self.results:
            fam = r.case.family
            if fam not in families:
                families[fam] = {"total": 0, "blocked": 0, "missed": 0}
            families[fam]["total"] += 1
            if r.blocked:
                families[fam]["blocked"] += 1
            else:
                families[fam]["missed"] += 1
                
        return {
            "total_cases": self.total_cases,
            "blocked": self.blocked,
            "missed": self.missed,
            "bypass_rate": round(self.bypass_rate, 2),
            "families": families,
            "bypasses": [
                {"id": r.case.test_id, "family": r.case.family, "description": r.case.description, "upstream_calls": r.upstream_calls}
                for r in self.results if not r.blocked
            ]
        }

    def to_text(self) -> str:
        d = self.to_dict()
        lines = [
            "AgentGuard Adversarial Authorization Benchmark",
            "==============================================",
            f"Total Cases: {d['total_cases']}",
            f"Blocked:     {d['blocked']}",
            f"Missed:      {d['missed']}",
            f"Bypass Rate: {d['bypass_rate']}%",
            "",
            "Families:"
        ]
        for fam, stats in d["families"].items():
            lines.append(f"  {fam}: {stats['blocked']}/{stats['total']} blocked")
            
        if d["bypasses"]:
            lines.append("\nBYPASSES (Missed Attacks):")
            for b in d["bypasses"]:
                lines.append(f"  - [{b['id']}] {b['family']}: {b['description']} (Upstream calls: {b['upstream_calls']})")
                
        return "\n".join(lines)


class AdversarialRunner:
    """Runs adversarial test cases against an AgentGuardGateway instance."""
    
    async def run_all(self, cases: list[AdversarialTestCase]) -> AdversarialReport:
        from unittest.mock import AsyncMock
        from agentguard.gateway.server import AgentGuardGateway
        from agentguard.policy.engine import PolicyEngine
        from agentguard.policy.defaults import DEFAULT_RULES
        from agentguard.events.store import EventStore
        from agentguard.intent.models import TaskIntent, ResourceConstraint
        from agentguard.intent.capabilities import Capability

        from agentguard.context.models import SecurityContext

        results = []
        
        for case in cases:
            # We create a fresh gateway for each case to ensure isolation
            mock_client = AsyncMock()
            
            class MockTool:
                def __init__(self, name):
                    self.name = name
                    self.description = "Mock tool"
                    self.inputSchema = {"type": "object"}
                    
            class MockListResult:
                tools = [MockTool(case.tool_name)]
                
            mock_client.list_tools = AsyncMock(return_value=MockListResult())
            mock_client.call_tool = AsyncMock(return_value=types.CallToolResult(content=[types.TextContent(type="text", text="Success")]))
            
            policy_engine = PolicyEngine(rules=DEFAULT_RULES)
            event_store = EventStore()
            
            # Setup intent that specifically ALLOWS the target capabilities and some baseline resources,
            # so the test proves the *resource* logic or *argument* logic correctly blocks the malicious variation.
            intent = TaskIntent(
                intent_id="adv-intent-1",
                description="Adversarial testing intent",
                allowed_capabilities=(Capability.FILE_READ, Capability.FILE_WRITE, Capability.NETWORK, Capability.TEST_EXECUTION),
                forbidden_capabilities=(Capability.PRIVILEGED,),
                required_outcomes=(),
                optional_outcomes=(),
                constraints=(),
                resource_constraints=(
                    ResourceConstraint(Capability.FILE_READ, ("/app/workspace",)),
                    ResourceConstraint(Capability.FILE_WRITE, ("/app/workspace",)),
                    ResourceConstraint(Capability.NETWORK, ("api.github.com",))
                )
            )
            
            context = SecurityContext(
                session_id="adv-session",
                agent_id="adv-agent",
                active_intent=intent
            )
            
            gateway = AgentGuardGateway(
                client_session=mock_client,
                policy_engine=policy_engine,
                event_store=event_store,
                security_context=context
            )
            
            # Observe tools so they are registered and not blocked as UNAPPROVED_NEW_TOOL
            await gateway.server._request_handlers["tools/list"].handler(None, None)
            
            call_handler = gateway.server._request_handlers["tools/call"].handler
            req = types.CallToolRequestParams(name=case.tool_name, arguments=case.arguments)
            
            res = await call_handler(None, req)
            
            upstream_calls = mock_client.call_tool.call_count
            
            # If the response is an error (DENY), then it was blocked.
            # If it's not an error (ALLOW), it's a bypass.
            blocked = res.is_error
            explanation = res.content[0].text if blocked else "Bypass: Upstream execution allowed"
            
            results.append(AdversarialResult(
                case=case,
                blocked=blocked,
                explanation=explanation,
                upstream_calls=upstream_calls
            ))
            
        return AdversarialReport(results)
