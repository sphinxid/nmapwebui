"""
Input sanitization utilities to protect against command injection and other security vulnerabilities.
This module provides a centralized set of functions for sanitizing user input across the application.
"""

import re
import ipaddress
from typing import Union, List, Optional, Dict, Any

def sanitize_ip_address(ip: str) -> Optional[str]:
    """
    Sanitize and validate an IP address or CIDR notation.
    
    Args:
        ip: The IP address or CIDR notation to validate
        
    Returns:
        The validated IP address/CIDR or None if invalid
    """
    ip = ip.strip()
    
    try:
        # Check if it's a valid IP or CIDR
        if '/' in ip:  # CIDR notation
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None

def sanitize_hostname(hostname: str) -> Optional[str]:
    """
    Sanitize and validate a hostname.
    
    Args:
        hostname: The hostname to validate
        
    Returns:
        The validated hostname or None if invalid
    """
    hostname = hostname.strip().lower()
    
    # Hostname validation regex (RFC 1123)
    hostname_pattern = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    
    if re.match(hostname_pattern, hostname):
        return hostname
    return None

def sanitize_port(port: Union[str, int]) -> Optional[int]:
    """
    Sanitize and validate a port number.
    
    Args:
        port: The port number to validate
        
    Returns:
        The validated port as an integer or None if invalid
    """
    try:
        port_num = int(port)
        if 1 <= port_num <= 65535:
            return port_num
        return None
    except (ValueError, TypeError):
        return None

def sanitize_port_range(port_range: str) -> Optional[str]:
    """
    Sanitize and validate a port range (e.g., "80-443").
    
    Args:
        port_range: The port range to validate
        
    Returns:
        The validated port range or None if invalid
    """
    port_range = port_range.strip()
    
    # Single port
    if port_range.isdigit():
        port = sanitize_port(port_range)
        return str(port) if port else None
    
    # Port range (e.g., 80-443)
    if '-' in port_range:
        parts = port_range.split('-')
        if len(parts) == 2:
            start = sanitize_port(parts[0])
            end = sanitize_port(parts[1])
            if start and end and start <= end:
                return f"{start}-{end}"
    
    return None

def sanitize_nmap_target(target: str) -> Optional[str]:
    """
    Sanitize and validate an Nmap target (IP, hostname, or CIDR).
    
    Args:
        target: The target to validate
        
    Returns:
        The validated target or None if invalid
    """
    target = target.strip()
    
    # Check if it's an IP address or CIDR
    ip_result = sanitize_ip_address(target)
    if ip_result:
        return ip_result
    
    # Check if it's a hostname
    hostname_result = sanitize_hostname(target)
    if hostname_result:
        return hostname_result
    
    return None

def sanitize_nmap_targets(targets: str) -> List[str]:
    """
    Sanitize and validate a list of Nmap targets (comma or space-separated).
    
    Args:
        targets: The targets to validate (comma or space-separated)
        
    Returns:
        List of validated targets (empty list if all invalid)
    """
    # Split by comma or space
    if ',' in targets:
        target_list = [t.strip() for t in targets.split(',')]
    else:
        target_list = [t.strip() for t in targets.split()]
    
    # Filter out empty strings
    target_list = [t for t in target_list if t]
    
    # Sanitize each target
    valid_targets = []
    for target in target_list:
        sanitized = sanitize_nmap_target(target)
        if sanitized:
            valid_targets.append(sanitized)
    
    return valid_targets

def sanitize_nmap_command(command: str) -> Optional[str]:
    """
    Sanitize an Nmap command to prevent command injection.
    Removes potentially dangerous characters and options.
    
    Args:
        command: The Nmap command to sanitize
        
    Returns:
        The sanitized command or None if the command contains disallowed options
    """
    # Disallowed options that could be used for command injection
    disallowed_options = [
        '--script-args=',
        '--script-args-file=',
        '-iL',
        '--script-help=',
        '--script-trace',
        '--interactive',
        '--exec',
        '--execute',
        '-c',
        ';',
        '&&',
        '||',
        '`',
        '$(',
        '${',
        '>',
        '<',
        '|',
        '*',
        '?',
        '~',
        '\\',
        '\n',
        '\r',
    ]
    
    # Check for disallowed options
    command = command.strip()
    for option in disallowed_options:
        if option in command:
            return None
    
    # Only allow alphanumeric characters, spaces, and a limited set of special characters
    # Include underscore to preserve filenames with underscores
    sanitized = re.sub(r'[^a-zA-Z0-9\s\-\.,/=:_]', '', command)
    
    return sanitized

def sanitize_form_data(form_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize form data based on field names.
    
    Args:
        form_data: Dictionary of form data
        
    Returns:
        Dictionary of sanitized form data
    """
    sanitized = {}
    
    for key, value in form_data.items():
        if not value:
            sanitized[key] = value
            continue
            
        if isinstance(value, (list, tuple)):
            sanitized[key] = value  # Keep lists/tuples as is for now
            continue
            
        if not isinstance(value, str):
            sanitized[key] = value  # Keep non-string values as is
            continue
            
        # Apply specific sanitization based on field name
        if 'ip' in key.lower() or key.lower() == 'target' or key.lower() == 'host':
            if ',' in value or ' ' in value:
                # Multiple targets
                sanitized[key] = ','.join(sanitize_nmap_targets(value))
            else:
                # Single target
                sanitized_value = sanitize_nmap_target(value)
                sanitized[key] = sanitized_value if sanitized_value else ''
        elif 'port' in key.lower():
            if '-' in value:
                sanitized_value = sanitize_port_range(value)
                sanitized[key] = sanitized_value if sanitized_value else ''
            else:
                sanitized_port = sanitize_port(value)
                sanitized[key] = str(sanitized_port) if sanitized_port else ''
        elif 'command' in key.lower() or 'args' in key.lower() or 'options' in key.lower():
            sanitized_value = sanitize_nmap_command(value)
            sanitized[key] = sanitized_value if sanitized_value else ''
        else:
            # Generic sanitization for other fields
            sanitized[key] = value.strip()
    
    return sanitized
