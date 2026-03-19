from comfy import high
import re


@high(
    name='rule_cve20250116',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_lldp_config='show config running | match "lldp"',
    ),
)
def rule_cve20250116(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0116 in PAN-OS configurations.
    A Denial of Service (DoS) vulnerability in Palo Alto Networks PAN-OS software causes the firewall 
    to unexpectedly reboot when processing a specially crafted LLDP frame sent by an unauthenticated 
    adjacent attacker. Repeated attempts to initiate this condition causes the firewall to enter maintenance mode.
    """
    # Extract system info
    version_output = commands.show_system_info
    lldp_config = commands.show_lldp_config
    
    def normalize_version(version_str: str) -> tuple:
        """Parse version string into comparable tuple"""
        match = re.search(r'(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?', version_str)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            hotfix = int(match.group(4)) if match.group(4) else 0
            return (major, minor, patch, hotfix)
        return (0, 0, 0, 0)
    
    def is_version_affected(device_version: str) -> bool:
        """Check if device version is in vulnerable range"""
        device_norm = normalize_version(device_version)
        
        # PAN-OS 11.2: < 11.2.5
        if device_norm >= (11, 2, 0, 0) and device_norm < (11, 2, 5, 0):
            return True
        
        # PAN-OS 11.1: < 11.1.8 or < 11.1.6-h6 or < 11.1.4-h17
        if device_norm >= (11, 1, 0, 0) and device_norm < (11, 1, 8, 0):
            if device_norm < (11, 1, 4, 17):
                return True
            if (11, 1, 4, 17) <= device_norm < (11, 1, 6, 6):
                return True
            if device_norm >= (11, 1, 6, 6):
                return False
            return True
        
        # PAN-OS 10.2: < 10.2.14 or < 10.2.13-h5 or < 10.2.10-h17
        if device_norm >= (10, 2, 0, 0) and device_norm < (10, 2, 14, 0):
            if device_norm < (10, 2, 10, 17):
                return True
            if (10, 2, 10, 17) <= device_norm < (10, 2, 13, 5):
                return True
            if device_norm >= (10, 2, 13, 5):
                return False
            return True
        
        # PAN-OS 10.1: < 10.1.14-h11
        if device_norm >= (10, 1, 0, 0) and device_norm < (10, 1, 14, 11):
            return True
        
        # PAN-OS 11.0, 10.0, 9.1, 9.0 and older (EoL - presumed affected)
        if device_norm < (10, 1, 0, 0):
            return True
        
        return False

    # Extract version from sw-version line
    version_match = re.search(r'sw-version:\s*(\S+)', version_output)
    if not version_match:
        return
    
    version = version_match.group(1)
    
    # Check if this is Cloud NGFW or Prisma Access (not vulnerable)
    model_match = re.search(r'model:\s*(\S+)', version_output)
    if model_match:
        model = model_match.group(1)
        if 'Cloud' in model or 'Prisma' in model:
            return
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if LLDP is enabled and configured in a vulnerable way
    lldp_enabled = False
    lldp_vulnerable_mode = False
    
    # Check if LLDP is enabled globally
    if re.search(r'set\s+network\s+lldp\s+enable\s+yes', lldp_config, re.IGNORECASE):
        lldp_enabled = True
    
    # Check if LLDP is enabled on any interface
    if re.search(r'set\s+network\s+interface\s+\S+\s+lldp\s+enable\s+yes', lldp_config, re.IGNORECASE):
        lldp_enabled = True
    
    # Check if LLDP profile mode is set to receive-only or transmit-receive
    if re.search(r'set\s+network\s+profiles\s+lldp\s+\S+\s+mode\s+(receive-only|transmit-receive)', lldp_config, re.IGNORECASE):
        lldp_vulnerable_mode = True
    
    # Device is vulnerable if LLDP is enabled and mode is vulnerable
    if lldp_enabled and lldp_vulnerable_mode:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-0116. "
            f"The device is running vulnerable version {version} with LLDP enabled in receive or transmit-receive mode. "
            "A specially crafted LLDP frame can cause the firewall to reboot unexpectedly. "
            "Mitigation: Disable LLDP globally, disable LLDP on interfaces, or set LLDP mode to 'transmit-only'. "
            "Recommended: Upgrade to a fixed version: 11.2.5+, 11.1.8+, 11.1.6-h6+, 11.1.4-h17+, "
            "10.2.14+, 10.2.13-h5+, 10.2.10-h17+, or 10.1.14-h11+. "
            "For more details see: https://security.paloaltonetworks.com/CVE-2025-0116"
        )