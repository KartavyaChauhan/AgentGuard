import os
import json
import socket
import pathlib
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import mcp.types as types

from agentguard.gateway.proxy import AgentGuardGateway
from agentguard.gateway.server import run_gateway
from agentguard.gateway.models import GatewayConfig
from agentguard.gateway.config import load_config
from agentguard.cli import run_gateway_command
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.models import ToolRequest, PolicyAction, PolicyDecision, RiskLevel
from agentguard.policy.rules import ToolNameRule, ArgumentPatternRule
from agentguard.intent.models import TaskIntent, ResourceConstraint
from agentguard.intent.capabilities import Capability
from agentguard.intent.resources import validate_file_read, validate_network
from agentguard.context.models import SecurityContext
from agentguard.events.store import EventStore
from agentguard.events.models import ToolEvent
from agentguard.audit.repository import AuditRepository
from agentguard.audit.database import AuditPersistenceError
from agentguard.audit.models import sanitize_arguments, create_audit_event_from_tool_event


@pytest.fixture
def mock_client_session():
    session = AsyncMock()
    
    class MockTool:
        def __init__(self, name):
            self.name = name
            self.description = "Mock tool"
            self.inputSchema = {"type": "object"}
            
    class MockListResult:
        tools = [
            MockTool("read_file"),
            MockTool("write_file"),
            MockTool("http_request"),
            MockTool("pytest"),
            MockTool("shell")
        ]
        
    session.list_tools.return_value = MockListResult()
    session.call_tool.return_value = types.CallToolResult(
        content=[types.TextContent(type="text", text="Upstream OK")],
        is_error=False
    )
    return session


# ==============================================================================
# Priority 1: Intent Enforcement & Gateway Wiring Regression Tests
# ==============================================================================

class TestPriority1IntentGatewayWiring:
    @pytest.mark.anyio
    async def test_explicit_configured_intent_allows_operation(self, mock_client_session):
        """Test an explicitly configured intent allows an authorized operation."""
        intent = TaskIntent(
            intent_id="intent-read",
            description="Allow reading",
            allowed_capabilities=(Capability.FILE_READ,),
            forbidden_capabilities=(Capability.NETWORK,)
        )
        ctx = SecurityContext(session_id="s1", agent_id="a1", active_intent=intent)
        engine = PolicyEngine(rules=[])
        gateway = AgentGuardGateway(mock_client_session, engine, security_context=ctx)
        await gateway.server._request_handlers["tools/list"].handler(None, None)
        
        req = types.CallToolRequestParams(name="read_file", arguments={"path": "safe.txt"})
        res = await gateway.server._request_handlers["tools/call"].handler(None, req)
        
        assert not res.is_error
        assert mock_client_session.call_tool.call_count == 1
        assert res.content[0].text == "Upstream OK"

    @pytest.mark.anyio
    async def test_operation_prohibited_by_intent_is_blocked(self, mock_client_session):
        """Test an operation prohibited by intent is blocked and never reaches upstream."""
        intent = TaskIntent(
            intent_id="intent-no-network",
            description="No network allowed",
            allowed_capabilities=(Capability.FILE_READ,),
            forbidden_capabilities=(Capability.NETWORK,)
        )
        ctx = SecurityContext(session_id="s1", agent_id="a1", active_intent=intent)
        engine = PolicyEngine(rules=[])
        gateway = AgentGuardGateway(mock_client_session, engine, security_context=ctx)
        await gateway.server._request_handlers["tools/list"].handler(None, None)
        
        req = types.CallToolRequestParams(name="http_request", arguments={"url": "https://api.github.com"})
        res = await gateway.server._request_handlers["tools/call"].handler(None, req)
        
        assert res.is_error
        assert "not authorized by the active TaskIntent" in res.content[0].text
        # Upstream MCP server must NEVER be contacted
        assert mock_client_session.call_tool.call_count == 0

    @pytest.mark.anyio
    async def test_explicit_policy_denial_takes_precedence_over_intent_allow(self, mock_client_session, tmp_path):
        """Test an explicit policy denial takes precedence even when intent resource constraint matches."""
        ws = str(tmp_path)
        intent = TaskIntent(
            intent_id="intent-ws",
            description="Allow files in workspace",
            allowed_capabilities=(Capability.FILE_READ,),
            forbidden_capabilities=(),
            resource_constraints=(ResourceConstraint(Capability.FILE_READ, (ws,)),)
        )
        ctx = SecurityContext(session_id="s1", agent_id="a1", active_intent=intent)
        
        # Policy engine has an explicit rule denying reading specific file
        target_path = f"{ws}/forbidden.txt"
        deny_rule = ArgumentPatternRule(
            id="deny-forbidden-file",
            description="Deny forbidden.txt",
            tool_name="read_file",
            argument="path",
            pattern="forbidden.txt",
            action=PolicyAction.DENY
        )
        engine = PolicyEngine(rules=[deny_rule])
        gateway = AgentGuardGateway(mock_client_session, engine, security_context=ctx)
        await gateway.server._request_handlers["tools/list"].handler(None, None)
        
        req = types.CallToolRequestParams(name="read_file", arguments={"path": target_path})
        res = await gateway.server._request_handlers["tools/call"].handler(None, req)
        
        # The explicit policy rule must take precedence and block it!
        assert res.is_error
        assert "AgentGuard denied execution" in res.content[0].text
        assert mock_client_session.call_tool.call_count == 0

    @pytest.mark.anyio
    async def test_missing_intent_security_context_backward_compatibility(self, mock_client_session):
        """Test gateway when no SecurityContext or active_intent is supplied."""
        engine = PolicyEngine(rules=[])
        gateway = AgentGuardGateway(mock_client_session, engine, security_context=None)
        await gateway.server._request_handlers["tools/list"].handler(None, None)
        
        req = types.CallToolRequestParams(name="read_file", arguments={"path": "safe.txt"})
        res = await gateway.server._request_handlers["tools/call"].handler(None, req)
        
        assert not res.is_error
        assert mock_client_session.call_tool.call_count == 1

    @pytest.mark.anyio
    async def test_run_gateway_wires_security_context_to_gateway(self, mock_client_session):
        """Test that run_gateway forwards security_context to AgentGuardGateway."""
        intent = TaskIntent(
            intent_id="intent-test",
            description="Testing wiring",
            allowed_capabilities=(Capability.FILE_READ,),
            forbidden_capabilities=(Capability.NETWORK,)
        )
        ctx = SecurityContext(session_id="s-wired", agent_id="a-wired", active_intent=intent)
        cfg = GatewayConfig(upstream_command="python", upstream_args=["-m", "server"])
        engine = PolicyEngine(rules=[])
        store = EventStore()
        
        # Mock stdio_client and stdio_server
        with patch("agentguard.gateway.server.stdio_client") as mock_stdio, \
             patch("agentguard.gateway.server.ClientSession") as mock_cs_cls, \
             patch("agentguard.gateway.server.stdio_server") as mock_server_stdio:
            
            mock_session = AsyncMock()
            mock_session.initialize = AsyncMock()
            mock_cs_cls.return_value.__aenter__.return_value = mock_session
            
            mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
            mock_server_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
            
            with patch("agentguard.gateway.server.AgentGuardGateway") as mock_gw_cls:
                mock_gw = MagicMock()
                mock_gw.server.run = AsyncMock()
                mock_gw.server.create_initialization_options = MagicMock()
                mock_gw_cls.return_value = mock_gw
                
                await run_gateway(cfg, engine, store, security_context=ctx)
                
                mock_gw_cls.assert_called_once_with(
                    client_session=mock_session,
                    policy_engine=engine,
                    event_store=store,
                    security_context=ctx
                )


# ==============================================================================
# Priority 2: SSRF and Outbound Network Restrictions Regression Tests
# ==============================================================================

class TestPriority2SSRFAndNetworkRestrictions:
    def test_ipv4_mapped_ipv6_loopback_blocked(self):
        """Test that IPv4-mapped IPv6 loopback addresses are blocked."""
        allowed, reason = validate_network("http://[::ffff:127.0.0.1]")
        assert not allowed
        assert "loopback" in reason.lower()

    def test_ipv4_mapped_ipv6_metadata_blocked(self):
        """Test that IPv4-mapped IPv6 cloud metadata addresses are blocked."""
        allowed, reason = validate_network("http://[::ffff:169.254.169.254]")
        assert not allowed
        assert "metadata" in reason.lower() or "link-local" in reason.lower()

    def test_ipv4_mapped_ipv6_private_blocked(self):
        """Test that IPv4-mapped IPv6 private network addresses are blocked."""
        allowed, reason = validate_network("http://[::ffff:10.0.0.1]")
        assert not allowed
        assert "private" in reason.lower()

    def test_unspecified_ip_addresses_blocked(self):
        """Test that 0.0.0.0 and [::] are blocked."""
        allowed, reason = validate_network("http://0.0.0.0")
        assert not allowed
        assert "unspecified" in reason.lower()
        
        allowed, reason = validate_network("http://0.0.0.0:8080")
        assert not allowed
        
        allowed, reason = validate_network("http://[::]")
        assert not allowed

    def test_decimal_and_hex_ip_representations_blocked(self):
        """Test that integer and hexadecimal IP representations of 127.0.0.1 are blocked."""
        # 2130706433 is 127.0.0.1 in decimal integer
        allowed, reason = validate_network("http://2130706433")
        assert not allowed
        assert "loopback" in reason.lower()
        
        # 0x7f000001 is 127.0.0.1 in hexadecimal
        allowed, reason = validate_network("http://0x7f000001")
        assert not allowed
        assert "loopback" in reason.lower()

    def test_octal_and_dotted_short_representations_blocked(self):
        """Test octal and shortened IP representations of loopback are blocked."""
        allowed, reason = validate_network("http://0177.0.0.1")
        assert not allowed
        assert "loopback" in reason.lower()

    def test_url_encoded_hostnames_blocked(self):
        """Test URL percent-encoded loopback hostname is decoded and blocked."""
        # %31%32%37%2E%30%2E%30%2E%31 is 127.0.0.1
        allowed, reason = validate_network("http://%31%32%37%2E%30%2E%30%2E%31")
        assert not allowed
        assert "loopback" in reason.lower()

    def test_dns_resolution_to_private_ip_blocked(self):
        """Test that hostnames resolving to private/loopback IPs are blocked."""
        # Mock socket.getaddrinfo to simulate a DNS rebinding/spoofed domain
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            allowed, reason = validate_network("http://spoofed-domain.test")
            assert not allowed
            assert "resolves to restricted ip address" in reason.lower()
            assert "loopback" in reason.lower()

    def test_dns_resolution_to_metadata_ip_blocked(self):
        """Test that hostnames resolving to 169.254.169.254 are blocked."""
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 80))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            allowed, reason = validate_network("http://metadata.spoofed.test")
            assert not allowed
            assert "metadata" in reason.lower()

    def test_legitimate_external_network_requests_allowed(self):
        """Test that legitimate public domains are permitted."""
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('140.82.112.4', 443))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            allowed, reason = validate_network("https://api.github.com/v1")
            assert allowed
            assert reason == "URL is allowed."

    @pytest.mark.anyio
    async def test_gateway_blocks_ssrf_without_contacting_upstream(self, mock_client_session):
        """Test that SSRF attempts through gateway never trigger upstream calls."""
        intent = TaskIntent(
            intent_id="intent-net",
            description="Network intent",
            allowed_capabilities=(Capability.NETWORK,),
            forbidden_capabilities=()
        )
        ctx = SecurityContext(session_id="s-ssrf", agent_id="a-ssrf", active_intent=intent)
        engine = PolicyEngine(rules=[])
        gateway = AgentGuardGateway(mock_client_session, engine, security_context=ctx)
        await gateway.server._request_handlers["tools/list"].handler(None, None)
        
        # Test IPv4-mapped IPv6 SSRF
        req = types.CallToolRequestParams(name="http_request", arguments={"url": "http://[::ffff:127.0.0.1]"})
        res = await gateway.server._request_handlers["tools/call"].handler(None, req)
        
        assert res.is_error
        assert "Resource constraint violation" in res.content[0].text
        assert mock_client_session.call_tool.call_count == 0


# ==============================================================================
# Priority 3: File Path & Workspace Isolation Regression Tests
# ==============================================================================

class TestPriority3FilePathAndWorkspaceIsolation:
    def test_windows_alternate_data_streams_blocked(self):
        """Test that Windows NTFS Alternate Data Streams (::$DATA) cannot bypass sensitive file block."""
        allowed, reason = validate_file_read(".env::$DATA")
        assert not allowed
        assert "sensitive resource" in reason.lower()
        
        allowed, reason = validate_file_read("app/.env::$DATA")
        assert not allowed
        assert "sensitive resource" in reason.lower()

    def test_repeated_url_encoding_traversal_blocked(self):
        """Test double/nested percent-encoded path traversal is blocked."""
        # %252E%252E%252F is double-encoded ../
        allowed, reason = validate_file_read("%252E%252E%252Fsecret.txt")
        assert not allowed
        assert "traversal" in reason.lower()

    def test_credential_files_blocked(self):
        """Test sensitive credential file patterns are blocked."""
        allowed, reason = validate_file_read("credentials.json")
        assert not allowed
        assert "sensitive resource" in reason.lower()
        
        allowed, reason = validate_file_read("/app/config/credentials.json")
        assert not allowed
        assert "sensitive resource" in reason.lower()

    def test_workspace_isolation_case_normalization(self, tmp_path):
        """Test workspace isolation normalizes path cases on case-insensitive systems."""
        ws = str(tmp_path)
        # Safe inside workspace
        allowed, reason = validate_file_read(f"{ws}/safe.txt", [ws])
        assert allowed
        
        # Outside workspace
        outside = str(tmp_path.parent / "outside_dir" / "secret.txt")
        allowed, reason = validate_file_read(outside, [ws])
        assert not allowed
        assert "outside" in reason.lower()

    @pytest.mark.anyio
    async def test_gateway_blocks_file_traversal_without_contacting_upstream(self, mock_client_session, tmp_path):
        """Test file path violation through gateway never triggers upstream calls."""
        ws = str(tmp_path)
        intent = TaskIntent(
            intent_id="intent-file",
            description="File intent",
            allowed_capabilities=(Capability.FILE_READ,),
            forbidden_capabilities=(),
            resource_constraints=(ResourceConstraint(Capability.FILE_READ, (ws,)),)
        )
        ctx = SecurityContext(session_id="s-file", agent_id="a-file", active_intent=intent)
        engine = PolicyEngine(rules=[])
        gateway = AgentGuardGateway(mock_client_session, engine, security_context=ctx)
        await gateway.server._request_handlers["tools/list"].handler(None, None)
        
        # Traverse out
        req = types.CallToolRequestParams(name="read_file", arguments={"path": f"{ws}/../../etc/passwd"})
        res = await gateway.server._request_handlers["tools/call"].handler(None, req)
        
        assert res.is_error
        assert "Resource constraint violation" in res.content[0].text
        assert mock_client_session.call_tool.call_count == 0


# ==============================================================================
# Priority 4: Audit Integrity & Event-Store Configuration Regression Tests
# ==============================================================================

class TestPriority4AuditIntegrityAndEventStore:
    def test_load_config_rejects_unsupported_event_store(self, tmp_path):
        """Test that invalid event_store backends are rejected with ValueError."""
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({
            "upstream": "python -m srv",
            "event_store": "unsupported_backend"
        }), encoding="utf-8")
        
        with pytest.raises(ValueError, match="Unsupported event_store backend"):
            load_config(str(cfg_path))

    def test_load_config_accepts_valid_event_stores(self, tmp_path):
        """Test that memory and sqlite event_store backends are accepted."""
        for backend in ("memory", "sqlite"):
            cfg_path = tmp_path / f"config_{backend}.json"
            cfg_path.write_text(json.dumps({
                "upstream": "python -m srv",
                "event_store": backend
            }), encoding="utf-8")
            cfg = load_config(str(cfg_path))
            assert cfg.event_store == backend

    def test_run_gateway_command_wires_sqlite_event_store(self, tmp_path):
        """Test run_gateway_command wires AuditRepository when event_store is sqlite."""
        db_file = tmp_path / "audit.db"
        cfg_path = tmp_path / "config_sqlite.json"
        cfg_path.write_text(json.dumps({
            "upstream": "python -m srv",
            "event_store": "sqlite"
        }), encoding="utf-8")
        
        args = MagicMock()
        args.config = str(cfg_path)
        args.upstream = None
        
        with patch.dict(os.environ, {"AGENTGUARD_AUDIT_DB": str(db_file)}), \
             patch("agentguard.gateway.server.run_gateway", new_callable=AsyncMock) as mock_run:
            
            exit_code = run_gateway_command(args)
            assert exit_code == 0
            mock_run.assert_called_once()
            called_cfg, called_engine, called_store = mock_run.call_args[0]
            assert called_cfg.event_store == "sqlite"
            assert called_store._audit_repository is not None
            assert called_store._audit_repository.db_path == str(db_file)

    def test_audit_verification_detects_cross_session_reassignment(self, tmp_path):
        """Test that moving an event to another session breaks verification."""
        db_path = str(tmp_path / "audit_test.sqlite3")
        repo = AuditRepository(db_path)
        repo.create_database()
        
        store = EventStore(audit_repository=repo)
        
        from datetime import datetime, timezone
        event1 = ToolEvent(
            event_id="ev-1",
            timestamp=datetime.now(timezone.utc),
            session_id="session-orig",
            agent_id="agent-1",
            tool_name="read_file",
            arguments={"path": "safe.txt"},
            policy_action=PolicyAction.ALLOW,
            risk_level=RiskLevel.LOW,
            execution_status=PolicyAction.ALLOW,
            duration_ms=5.0
        )
        store.record(event1)
        
        # Verify clean session
        res = repo.verify_chain("session-orig")
        assert res.valid
        
        # Tamper directly in DB: reassign session_id to session-hacked
        with repo._get_conn() as conn:
            conn.execute("UPDATE audit_events SET session_id = 'session-hacked' WHERE event_id = 'ev-1'")
            conn.commit()
            
        # Verification of session-hacked must fail because hash included original session_id
        res_hacked = repo.verify_chain("session-hacked")
        assert not res_hacked.valid
        assert "Tampered event" in res_hacked.reason

    def test_audit_persistence_failure_fails_safely(self):
        """Test that audit repository persistence failures fail safely without crashing EventStore."""
        mock_repo = MagicMock()
        mock_repo.get_session_events.return_value = []
        mock_repo.append.side_effect = AuditPersistenceError("Simulated disk full")
        
        store = EventStore(audit_repository=mock_repo)
        
        from datetime import datetime, timezone
        event = ToolEvent(
            event_id="ev-fail",
            timestamp=datetime.now(timezone.utc),
            session_id="session-safe",
            agent_id="agent-1",
            tool_name="read_file",
            arguments={"path": "test.txt"},
            policy_action=PolicyAction.ALLOW,
            risk_level=RiskLevel.LOW,
            execution_status=PolicyAction.ALLOW,
            duration_ms=1.0
        )
        
        # Should NOT raise exception (side-channel isolated)
        store.record(event)
        
        # In-memory store still has event recorded
        assert store.get("ev-fail") is not None
        assert store.count("session-safe") == 1

    def test_audit_sanitizes_sensitive_arguments(self):
        """Test that sensitive argument values are scrubbed in audit records."""
        raw_args = {
            "api_key": "SUPER_SECRET_12345",
            "password": "my_secret_password",
            "count": 42,
            "verbose": True,
            "items": ["a", "b", "c"]
        }
        sanitized = sanitize_arguments(raw_args)
        
        assert "SUPER_SECRET_12345" not in str(sanitized)
        assert "my_secret_password" not in str(sanitized)
        assert sanitized["api_key"] == "<str, len=18>"
        assert sanitized["password"] == "<str, len=18>"
        assert sanitized["count"] == "<int>"
        assert sanitized["verbose"] == "<bool>"
        assert sanitized["items"] == "<list, len=3>"

    def test_network_cgnat_and_special_use_addresses_blocked(self):
        """Test Carrier-Grade NAT (100.64.0.0/10) and documentation IP ranges are blocked."""
        # 100.64.0.1 is CGNAT (is_private=False, is_global=False)
        allowed, reason = validate_network("http://100.64.0.1:8080/metrics")
        assert not allowed
        assert "not allowed" in reason.lower()

        # 198.51.100.1 is TEST-NET-2
        allowed, reason = validate_network("http://198.51.100.1/test")
        assert not allowed

        # 2001:db8::1 is IPv6 documentation prefix
        allowed, reason = validate_network("http://[2001:db8::1]/")
        assert not allowed

    def test_network_multicast_addresses_blocked(self):
        """Test IPv4 and IPv6 multicast addresses are blocked."""
        # 224.0.0.1 is IPv4 multicast
        allowed, reason = validate_network("http://224.0.0.1/stream")
        assert not allowed
        assert "multicast" in reason.lower() or "not allowed" in reason.lower()

        # ff02::1 is IPv6 multicast
        allowed, reason = validate_network("http://[ff02::1]/stream")
        assert not allowed

    def test_network_scoped_ipv6_addresses_blocked(self):
        """Test scoped IPv6 addresses with zone indices (%eth0) are blocked."""
        allowed, reason = validate_network("http://[fe80::1%25eth0]:8080/metadata")
        assert not allowed
        assert "link-local" in reason.lower() or "not allowed" in reason.lower()

    def test_unc_paths_blocked_before_resolution(self):
        """Test UNC network paths (\\\\server\\share) are blocked immediately to prevent SMB NTLM leaks."""
        allowed, reason = validate_file_read(r"\\192.168.1.1\share\secret.txt", allowed_workspaces=["/workspace"])
        assert not allowed
        assert "unc and network share" in reason.lower()

        allowed_fwd, reason_fwd = validate_file_read("//attacker.com/share/payload", allowed_workspaces=["/workspace"])
        assert not allowed_fwd
        assert "unc and network share" in reason_fwd.lower()

    def test_capabilities_network_and_file_tool_aliases(self):
        """Test common aliases for network and file tools map correctly."""
        from agentguard.intent.capabilities import capability_for_tool, Capability
        assert capability_for_tool("fetch") == Capability.NETWORK
        assert capability_for_tool("curl") == Capability.NETWORK
        assert capability_for_tool("wget") == Capability.NETWORK
        assert capability_for_tool("fetch_url") == Capability.NETWORK
        assert capability_for_tool("send_http_request") == Capability.NETWORK
        assert capability_for_tool("request") == Capability.NETWORK

        assert capability_for_tool("file_read") == Capability.FILE_READ
        assert capability_for_tool("get_file") == Capability.FILE_READ

    def test_cli_gateway_policy_override_flag(self, tmp_path):
        """Test CLI --policy flag overrides policies defined in config file."""
        import argparse
        import json
        from unittest.mock import AsyncMock, patch
        from agentguard.cli import run_gateway_command

        policy_file = tmp_path / "cli_override_policy.json"
        policy_file.write_text(json.dumps({
            "rules": [
                {
                    "type": "tool_name",
                    "id": "deny-via-flag",
                    "description": "Deny via flag",
                    "tool_name": "flagged_tool"
                }
            ]
        }))

        config_file = tmp_path / "gateway_base.json"
        config_file.write_text(json.dumps({
            "upstream": "python -m dummy",
            "policies": "default"
        }))

        args = argparse.Namespace(
            config=str(config_file),
            upstream=None,
            policy=str(policy_file)
        )

        with patch("agentguard.gateway.server.run_gateway", new_callable=AsyncMock) as mock_run:
            exit_code = run_gateway_command(args)
            assert exit_code == 0
            mock_run.assert_called_once()
            _, called_engine, _ = mock_run.call_args[0]
            assert len(called_engine.rules) == 1
            assert called_engine.rules[0].id == "deny-via-flag"

    def test_sensitive_files_blocked_case_insensitively(self):
        """Test sensitive file checks cannot be bypassed using uppercase or mixed case."""
        for sensitive in [".ENV", ".Git/config", "ID_RSA", "Passwd", "Credentials.json"]:
            allowed, reason = validate_file_read(sensitive)
            assert not allowed, f"Expected {sensitive} to be blocked"
            assert "sensitive resource" in reason.lower()

    def test_workspace_prefix_lookalike_blocked(self, tmp_path):
        """Test /workspace-evil is rejected when /workspace is allowed."""
        ws = str(tmp_path / "workspace")
        lookalike = str(tmp_path / "workspace-evil" / "secret.txt")
        allowed, reason = validate_file_read(lookalike, allowed_workspaces=[ws])
        assert not allowed
        assert "outside of all allowed workspaces" in reason.lower()

    def test_network_malformed_urls_and_unsupported_schemes_fail_safely(self):
        """Test malformed URLs and non-HTTP(S) schemes fail closed."""
        for bad_url in [
            "not-a-url",
            "file:///etc/passwd",
            "gopher://127.0.0.1:70",
            "ftp://example.com/file",
            "http://",
            "https://:443",
        ]:
            allowed, reason = validate_network(bad_url)
            assert not allowed, f"Expected {bad_url} to be blocked"


