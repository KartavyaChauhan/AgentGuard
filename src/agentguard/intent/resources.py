import os
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
        
    # 1. Decode URL encoding iteratively (up to 5 passes) to defeat nested/repeated percent-encoding
    decoded_path = path_arg
    for _ in range(5):
        next_decoded = urllib.parse.unquote(decoded_path)
        if next_decoded == decoded_path:
            break
        decoded_path = next_decoded
    
    # 2. Check for explicit traversal sequences before normalization to catch encoded bypasses
    normalized_for_traversal = decoded_path.replace('\\', '/')
    if "../" in normalized_for_traversal or "..\\" in decoded_path or "/.." in normalized_for_traversal or normalized_for_traversal.endswith(".."):
        return False, "Path traversal sequences are not allowed."
        
    # 2b. Block UNC and network share paths (e.g. \\server\share or //server/share)
    # Resolving UNC paths on Windows triggers OS-level SMB connections, causing NTLM theft or network hangs
    if decoded_path.replace('/', '\\').startswith('\\\\'):
        return False, "UNC and network share paths are not allowed."
        
    # 3. Detect Windows Alternate Data Streams (ADS) e.g. file.txt::$DATA or .env:hidden
    has_ads = False
    clean_path_for_resolve = decoded_path
    colon_idx = decoded_path.find(":")
    if colon_idx != -1:
        # On Windows, drive letter C:\ has ':' at index 1, which is not an ADS stream.
        if colon_idx != 1 or ":" in decoded_path[2:]:
            has_ads = True
            stream_start = decoded_path.find(":", 2 if colon_idx == 1 else 0)
            clean_path_for_resolve = decoded_path[:stream_start]

    # 4. Normalize path
    try:
        path = pathlib.Path(clean_path_for_resolve).resolve()
    except Exception as e:
        return False, f"Failed to resolve path: {str(e)}"
        
    path_str = str(path).replace('\\', '/')
    
    # 5. Deny sensitive files based on patterns
    # Skip if explicitly exactly matched in allowed_workspaces
    is_exact_match = False
    if allowed_workspaces:
        for ws in allowed_workspaces:
            try:
                ws_path = str(pathlib.Path(ws).resolve()).replace('\\', '/')
                path_match = (path_str.lower() == ws_path.lower()) if os.name == 'nt' else (path_str == ws_path)
                if path_match:
                    is_exact_match = True
                    break
            except Exception:
                pass
                
    if not is_exact_match:
        sensitive_patterns = [
            "/.env", "/.git", "/.ssh", "/id_rsa", "/id_ed25519", "/id_ecdsa", "/id_dsa",
            "/passwd", "/shadow", "/credentials.json"
        ]
        # Check if any sensitive pattern is part of the path structure (case-insensitive for safety)
        bounded_path = "/" + path_str.strip("/")
        bounded_path_lower = bounded_path.lower()
        
        for pattern in sensitive_patterns:
            if pattern in bounded_path_lower:
                idx = bounded_path_lower.find(pattern)
                boundary_char = bounded_path_lower[idx + len(pattern)] if idx + len(pattern) < len(bounded_path_lower) else None
                if boundary_char is None or boundary_char in ('/', '.', ':', ';'):
                    return False, f"Access to sensitive resource matching '{pattern}' is denied."

        # If an Alternate Data Stream was targeted on a sensitive pattern, block it
        if has_ads:
            raw_bounded_lower = "/" + decoded_path.replace('\\', '/').strip("/").lower()
            for pattern in sensitive_patterns:
                if pattern in raw_bounded_lower:
                    idx = raw_bounded_lower.find(pattern)
                    boundary_char = raw_bounded_lower[idx + len(pattern)] if idx + len(pattern) < len(raw_bounded_lower) else None
                    if boundary_char is None or boundary_char in ('/', '.', ':', ';'):
                        return False, f"Access to sensitive resource matching '{pattern}' is denied."

        # Deny specific absolute paths
        if "system32" in path_str.lower() or path_str.startswith("/etc/") or path_str.startswith("/var/log/"):
            return False, "Access to restricted system paths is denied."

    # 6. Workspace restriction
    if allowed_workspaces:
        is_in_workspace = False
        is_windows = (os.name == 'nt')
        path_cmp = path_str.lower() if is_windows else path_str
        for ws in allowed_workspaces:
            try:
                ws_resolved = str(pathlib.Path(ws).resolve()).replace('\\', '/')
                ws_cmp = ws_resolved.lower() if is_windows else ws_resolved
                if path_cmp == ws_cmp or path_cmp.startswith(ws_cmp + "/"):
                    is_in_workspace = True
                    break
            except Exception:
                pass
        
        if not is_in_workspace:
            return False, "Path is outside of all allowed workspaces."
            
    return True, "Path is allowed."


def _is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """Helper to evaluate whether an IP address targets loopback, private, or metadata networks."""
    if isinstance(ip, ipaddress.IPv6Address):
        # Handle IPv4-mapped IPv6 (::ffff:127.0.0.1, ::ffff:169.254.169.254, etc.)
        if ip.ipv4_mapped:
            return _is_ip_blocked(ip.ipv4_mapped)
        # Handle IPv4-compatible IPv6 (::127.0.0.1)
        if int(ip) > 1 and (int(ip) >> 32) == 0:
            return _is_ip_blocked(ipaddress.IPv4Address(int(ip)))
            
    if ip.is_unspecified:
        return True, "Unspecified addresses (like 0.0.0.0) are not allowed."
    if str(ip).split("%")[0] == "169.254.169.254":
        return True, "Cloud metadata endpoints are not allowed."
    if ip.is_loopback:
        return True, "Loopback addresses are not allowed."
    if ip.is_private:
        return True, "Private/internal addresses are not allowed."
    if ip.is_link_local:
        return True, "Link-local addresses (like cloud metadata) are not allowed."
    if ip.is_multicast:
        return True, "Multicast addresses are not allowed."
    if ip.is_reserved:
        return True, "Reserved addresses are not allowed."
    if not ip.is_global:
        return True, "Non-global or special-use addresses are not allowed."
        
    return False, ""


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
        
    # Unquote any percent-encoding in hostname (e.g. %31%32%37%2E%30%2E%30%2E%31)
    hostname = urllib.parse.unquote(hostname).lower()
    raw_ip_str = hostname.strip("[]")
    if "%" in raw_ip_str:
        raw_ip_str = raw_ip_str.split("%")[0]
    
    # 3. Reject common internal hostnames
    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
        or hostname.endswith(".lan")
    ):
        return False, "Internal network hostnames are not allowed."

    # 4. Parse and evaluate IP address representations (standard, decimal, hex, octal, IPv4-mapped)
    parsed_ip = None
    try:
        parsed_ip = ipaddress.ip_address(raw_ip_str)
    except ValueError:
        # Check decimal integer IP (e.g. 2130706433 -> 127.0.0.1)
        if raw_ip_str.isdigit():
            try:
                num = int(raw_ip_str)
                if 0 <= num <= 0xFFFFFFFF:
                    parsed_ip = ipaddress.IPv4Address(num)
            except ValueError:
                pass
        # Check hexadecimal IP (e.g. 0x7f000001 -> 127.0.0.1)
        elif raw_ip_str.startswith("0x"):
            try:
                num = int(raw_ip_str, 16)
                if 0 <= num <= 0xFFFFFFFF:
                    parsed_ip = ipaddress.IPv4Address(num)
            except ValueError:
                pass
        # Check octal / shortened dotted notation via socket.inet_aton
        elif all(part.isdigit() for part in raw_ip_str.split(".")) and raw_ip_str.count(".") in (1, 2, 3):
            try:
                import socket
                packed = socket.inet_aton(raw_ip_str)
                parsed_ip = ipaddress.IPv4Address(packed)
            except (ValueError, OSError, socket.error):
                pass

    if parsed_ip is not None:
        blocked, reason = _is_ip_blocked(parsed_ip)
        if blocked:
            return False, reason
    else:
        # Resolve hostname via DNS to prevent SSRF via domains pointing to internal IPs
        try:
            import socket
            resolved_infos = socket.getaddrinfo(hostname, None)
            for info in resolved_infos:
                sockaddr = info[4]
                ip_str = sockaddr[0]
                try:
                    res_ip = ipaddress.ip_address(ip_str)
                    blocked, reason = _is_ip_blocked(res_ip)
                    if blocked:
                        return False, f"Hostname '{hostname}' resolves to restricted IP address '{res_ip}': {reason}"
                except ValueError:
                    pass
        except (socket.gaierror, socket.herror, OSError):
            pass

    # 5. Hostname restriction
    if allowed_hosts:
        if hostname not in [h.lower() for h in allowed_hosts]:
            return False, f"Hostname '{hostname}' is not in the list of allowed hosts."
            
    return True, "URL is allowed."

