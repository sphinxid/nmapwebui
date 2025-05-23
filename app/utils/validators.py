import re
import socket
from ipaddress import ip_network, ip_address
from app.utils.sanitize import sanitize_ip_address, sanitize_hostname, sanitize_nmap_command, sanitize_nmap_target

def validate_targets(targets_list):
    """
    Validate a list of targets and categorize them
    Returns (valid_targets, invalid_targets)
    valid_targets is a list of tuples (target_value, target_type)
    
    This function now uses the sanitize module for more robust validation.
    """
    valid_targets = []
    invalid_targets = []
    
    for target in targets_list:
        target = target.strip()
        if not target:
            continue
        
        # Use our sanitization functions to validate the target
        # Check if it's a CIDR subnet
        if '/' in target:
            sanitized = sanitize_ip_address(target)
            if sanitized:
                valid_targets.append((sanitized, 'cidr'))
            else:
                invalid_targets.append(target)
        
        # Check if it's an IP address without CIDR
        elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            sanitized = sanitize_ip_address(target)
            if sanitized:
                valid_targets.append((sanitized, 'ip'))
            else:
                invalid_targets.append(target)
        
        # Check if it's a hostname
        else:
            sanitized = sanitize_hostname(target)
            if sanitized:
                try:
                    # Try to resolve the hostname
                    socket.gethostbyname(sanitized)
                    valid_targets.append((sanitized, 'hostname'))
                except socket.gaierror:
                    # Still add it as a hostname even if it doesn't resolve
                    # It might be a valid hostname that's not in DNS
                    valid_targets.append((sanitized, 'hostname'))
            else:
                invalid_targets.append(target)
    
    return valid_targets, invalid_targets

def validate_nmap_args(args):
    """
    Validate Nmap arguments to prevent command injection
    Returns (is_valid, message)
    
    This function now uses the sanitize module for more robust validation.
    """
    if not args:
        return True, 'Arguments are valid'
    
    # Use our sanitization function for Nmap commands
    sanitized = sanitize_nmap_command(args)
    
    if sanitized is None:
        # Try to provide more specific error messages
        # Check for forbidden characters
        forbidden_chars = [';', '&&', '||', '`', '>', '<', '|', '$', '(', ')', '{', '}']
        for char in forbidden_chars:
            if char in args:
                return False, f'Character "{char}" is not allowed in Nmap arguments.'
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'sh\s+', r'bash\s+', r'python\s+', r'perl\s+', r'ruby\s+',
            r'exec\s+', r'eval\s+', r'system\s+', r'popen\s+', r'subprocess\s+',
            r'--script-args=', r'--script-args-file=', r'-iL', r'--script-help=',
            r'--script-trace', r'--interactive', r'--exec', r'--execute'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, args, re.IGNORECASE):
                return False, f'Suspicious pattern detected: {pattern.strip()}'
        
        # Generic error if no specific issue was found
        return False, 'Invalid or potentially dangerous Nmap arguments detected.'
    
    # If we got here, the arguments are valid but may have been sanitized
    if sanitized != args:
        return True, 'Arguments have been sanitized for security.'
    
    return True, 'Arguments are valid'
