from comfy import high
import re


@high(
    name='rule_cve20250115',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_management_interface='show running resource-monitor ingress-backlogs | match management',
    ),
)
def rule_cve20250115(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0115 in PAN-OS configurations.
    The vulnerability allows an authenticated admin on the PAN-OS CLI to read arbitrary files.
    The attacker must have network access to the management interface (web, SSH, console, or telnet).
    """
    # Extract system info
    version_output = commands.show_system_info
    
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
    
    def is_version_affected(device_version: str, versions: list) -> bool:
        """Check if device version is in vulnerable range"""
        device_norm = normalize_version(device_version)
        
        for version_range in versions:
            base_version = normalize_version(version_range['version'])
            cap_version = normalize_version(version_range['lessThan'])
            
            if base_version <= device_norm < cap_version:
                return True
                
        return False

    # Extract version from sw-version line
    version_match = re.search(r'sw-version:\s*(\S+)', version_output)
    if not version_match:
        return
    
    version = version_match.group(1)
    
    # Check if Cloud NGFW or Prisma Access (not affected)
    model_match = re.search(r'model:\s*(\S+)', version_output)
    if model_match:
        model = model_match.group(1)
        if 'Prisma' in model or 'Cloud' in model:
            return
    
    # Define version ranges for vulnerable versions
    vulnerable_version_ranges = [
        {'version': '10.1.0', 'lessThan': '10.1.14-h11'},
        {'version': '10.2.0', 'lessThan': '10.2.10-h18'},
        {'version': '10.2.10-h18', 'lessThan': '10.2.11'},
        {'version': '11.0.0', 'lessThan': '11.0.6'},
        {'version': '11.1.0', 'lessThan': '11.1.4-h17'},
        {'version': '11.1.4-h17', 'lessThan': '11.1.5'},
        {'version': '11.2.0', 'lessThan': '11.2.3'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if management interface is exposed
    # Look for management interface configuration in the device configuration
    config_str = str(configuration)
    
    # Check for management interface profile on dataplane interfaces
    has_mgmt_profile = bool(re.search(r'interface-management-profile', config_str))
    
    # Check for permitted IP addresses restriction
    has_permitted_ip = bool(re.search(r'permitted-ip', config_str))
    
    # Check for management interface services enabled.
    # "disable-X no" means the service is enabled; "X yes/enable" also means enabled.
    has_mgmt_services = bool(
        re.search(r'disable-(https?|ssh|telnet)\s+no\b', config_str, re.IGNORECASE)
        or re.search(r'(?<!disable-)\b(https?|ssh|telnet)\s+(yes|enable)\b', config_str, re.IGNORECASE)
    )
    
    # If management interface is configured with services but no IP restrictions, it's vulnerable
    if has_mgmt_services and not has_permitted_ip:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-0115. "
            f"The device is running vulnerable PAN-OS version {version} and has management interface "
            "services enabled without proper IP address restrictions. "
            "An authenticated admin on the PAN-OS CLI can read arbitrary files. "
            "Upgrade to a fixed version: 10.1.14-h11+, 10.2.10-h18+, 10.2.11+, 11.0.6+, 11.1.4-h17+, 11.1.5+, 11.2.3+, or later. "
            "Alternatively, restrict management interface access to only trusted internal IP addresses. "
            "For more details see: https://security.paloaltonetworks.com/CVE-2025-0115"
        )
    
    # If management profile is configured on dataplane without restrictions, it's vulnerable
    if has_mgmt_profile and not has_permitted_ip:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-0115. "
            f"The device is running vulnerable PAN-OS version {version} and has management interface profile "
            "configured on dataplane interfaces without proper IP address restrictions. "
            "An authenticated admin on the PAN-OS CLI can read arbitrary files. "
            "Upgrade to a fixed version: 10.1.14-h11+, 10.2.10-h18+, 10.2.11+, 11.0.6+, 11.1.4-h17+, 11.1.5+, 11.2.3+, or later. "
            "Alternatively, restrict management interface access to only trusted internal IP addresses. "
            "For more details see: https://security.paloaltonetworks.com/CVE-2025-0115"
        )