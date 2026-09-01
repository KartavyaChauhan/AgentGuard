import ipaddress
import pathlib
import urllib.parse
from typing import Sequence


def validate_file_read(path_arg: str, allowed_workspaces: Sequence[str] = ()) -> tuple[bool, str]:
    """
    Validate a file read operation deterministically.
    
    Args:
        path_arg: The raw path argument from the tool request.
        allowed_workspaces: Optional list of allowed absolute directory paths.
        
    Returns:
        A tuple of (is_allowed: bool, reason: str).
    """
    if not isinstance(path_arg, str):
        return False, "Path argument must be a string."
        
    # 1. Decode URL encoding
    decoded_path = urllib.parse.unquote(path_arg)
    
    # 2. Check for explicit traversal sequences before normalization to catch encoded bypasses
    if "../" in decoded_path or "..\\" in decoded_path:
        return False, "Path traversal sequences are not allowed."
        
    # 3. Normalize path
    try:
        path = pathlib.Path(decoded_path).resolve()
    except Exception as e:
        return False, f"Failed to resolve path: {str(e)}"
        
    path_str = str(path).replace('\\', '/')
    
    # 4. Deny sensitive files based on patterns
    # Skip if explicitly exactly matched in allowed_workspaces
    is_exact_match = False
    if allowed_workspaces:
        for ws in allowed_workspaces:
            try:
                ws_path = str(pathlib.Path(ws).resolve()).replace('\\', '/')
                if path_str == ws_path:
                    is_exact_match = True
                    break
            except Exception:
                pass
                
    if not is_exact_match:
        sensitive_patterns = [
            "/.env", "/.git", "/.ssh", "/id_rsa", "/id_ed25519", "/passwd", "/shadow"
        ]
        # Check if any sensitive pattern is part of the path structure
        # We append and prepend '/' to the normalized path to easily match boundaries
        bounded_path = "/" + path_str.strip("/")
        
        for pattern in sensitive_patterns:
            if pattern in bounded_path:
                # Explicitly match boundaries, e.g. "/.env" must be followed by '/' or '.' or end of string
                idx = bounded_path.find(pattern)
                if idx + len(pattern) == len(bounded_path) or bounded_path[idx + len(pattern)] in ('/', '.'):
                    return False, f"Access to sensitive resource matching '{pattern}' is denied."

        # Deny specific absolute paths
        if "system32" in path_str.lower() or path_str.startswith("/etc/") or path_str.startswith("/var/log/"):
            return False, "Access to restricted system paths is denied."

    # 5. Workspace restriction
    if allowed_workspaces:
        is_in_workspace = False
        for ws in allowed_workspaces:
            ws_path = str(pathlib.Path(ws).resolve()).replace('\\', '/')
            # Ensure the resolved path starts with the workspace path
            if path_str.startswith(ws_path):
                # Ensure it's a true sub-path (not a substring trick like /work-other vs /work)
                if path_str == ws_path or path_str.startswith(ws_path + "/"):
                    is_in_workspace = True
                    break
        
        if not is_in_workspace:
            return False, "Path is outside of all allowed workspaces."
            
    return True, "Path is allowed."


def validate_network(url_arg: str, allowed_hosts: Sequence[str] = ()) -> tuple[bool, str]:
    """
    Validate a network operation deterministically.
    
    Args:
        url_arg: The raw URL argument from the tool request.
        allowed_hosts: Optional list of explicitly allowed hostnames.
        
    Returns:
        A tuple of (is_allowed: bool, reason: str).
    """
    if not isinstance(url_arg, str):
        return False, "URL argument must be a string."
        
    # 1. Parse URL
    try:
        parsed = urllib.parse.urlparse(url_arg)
    except Exception as e:
        return False, f"Failed to parse URL: {str(e)}"
        
    # 2. Validate Scheme
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported URL scheme: '{parsed.scheme}'. Only http and https are allowed."
        
    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a hostname."
        
    hostname = hostname.lower()
    
    # 3. Reject cloud metadata and internal IPs
    # First, test if it's an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        # Explicit check for 169.254.169.254 first
        if str(ip) == "169.254.169.254":
            return False, "Cloud metadata endpoints are not allowed."
        if ip.is_loopback:
            return False, "Loopback addresses are not allowed."
        if ip.is_private:
            return False, "Private/internal addresses are not allowed."
        if ip.is_link_local:
            return False, "Link-local addresses (like cloud metadata) are not allowed."
    except ValueError:
        # Not an IP address, which is fine
        pass
        
    # Reject common internal hostnames
    if hostname == "localhost" or hostname.endswith(".local") or hostname.endswith(".internal"):
        return False, "Internal network hostnames are not allowed."
        
    # 4. Hostname restriction
    if allowed_hosts:
        if hostname not in [h.lower() for h in allowed_hosts]:
            return False, f"Hostname '{hostname}' is not in the list of allowed hosts."
            
    return True, "URL is allowed."
