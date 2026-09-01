import os
import pathlib
import pytest

from agentguard.intent.resources import validate_file_read, validate_network

def test_validate_file_read_safe():
    allowed, reason = validate_file_read("test.txt")
    assert allowed
    
    allowed, reason = validate_file_read("/tmp/safe.txt")
    assert allowed


def test_validate_file_read_traversal():
    allowed, reason = validate_file_read("../secret.txt")
    assert not allowed
    assert "traversal" in reason.lower()
    
    allowed, reason = validate_file_read("..\\secret.txt")
    assert not allowed
    assert "traversal" in reason.lower()
    
    allowed, reason = validate_file_read("%2E%2E%2Fsecret.txt")
    assert not allowed
    assert "traversal" in reason.lower()


def test_validate_file_read_sensitive():
    allowed, reason = validate_file_read(".env")
    assert not allowed
    assert "sensitive resource" in reason.lower()
    
    allowed, reason = validate_file_read(".env.local")
    assert not allowed
    
    allowed, reason = validate_file_read(".git/config")
    assert not allowed
    
    allowed, reason = validate_file_read("~/.ssh/id_rsa")
    assert not allowed
    
    allowed, reason = validate_file_read("/etc/passwd")
    assert not allowed


def test_validate_file_read_workspace_restriction():
    ws_path = str(pathlib.Path("/allowed/workspace").resolve())
    
    # Safe path inside workspace
    allowed, reason = validate_file_read(f"{ws_path}/file.txt", [ws_path])
    assert allowed
    
    # Path outside workspace
    allowed, reason = validate_file_read("/other/workspace/file.txt", [ws_path])
    assert not allowed
    assert "outside" in reason.lower()
    
    # Sneaky prefix bypass (e.g. /allowed/workspace-evil)
    allowed, reason = validate_file_read(f"{ws_path}-evil/file.txt", [ws_path])
    assert not allowed


def test_validate_network_safe():
    allowed, reason = validate_network("https://api.github.com/v1")
    assert allowed
    
    allowed, reason = validate_network("http://example.com")
    assert allowed


def test_validate_network_internal():
    allowed, reason = validate_network("http://localhost:8080")
    assert not allowed
    assert "internal" in reason.lower() or "loopback" in reason.lower()
    
    allowed, reason = validate_network("http://127.0.0.1")
    assert not allowed
    
    allowed, reason = validate_network("http://169.254.169.254")
    assert not allowed
    assert "metadata" in reason.lower()
    
    allowed, reason = validate_network("http://192.168.1.1")
    assert not allowed
    assert "private" in reason.lower()
    
    allowed, reason = validate_network("http://10.0.0.5")
    assert not allowed
    
    allowed, reason = validate_network("http://my-service.local")
    assert not allowed


def test_validate_network_malformed():
    allowed, reason = validate_network("ftp://example.com")
    assert not allowed
    assert "unsupported" in reason.lower()
    
    allowed, reason = validate_network("not-a-url")
    assert not allowed


def test_validate_network_host_restriction():
    allowed_hosts = ["api.github.com", "example.com"]
    
    allowed, reason = validate_network("https://api.github.com/v1", allowed_hosts)
    assert allowed
    
    allowed, reason = validate_network("https://evil.com/v1", allowed_hosts)
    assert not allowed
    assert "not in the list" in reason.lower()
