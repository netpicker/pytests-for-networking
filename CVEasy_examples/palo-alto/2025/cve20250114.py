from comfy import high
import re


@high(
    name='rule_cve20250114',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_globalprotect_portals='show running resource-monitor second last 1',
    ),
)
def rule_cve20250114(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0114 in PAN-OS configurations.
    A Denial of Service (DoS) vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS 
    software enables an unauthenticated attacker to render the service unavailable by sending a large 
    number of specially crafted packets over a period of time. This issue affects both the GlobalProtect 
    portal and the GlobalProtect gateway.
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
    
    # Define version ranges for vulnerable versions
    vulnerable_version_ranges = [
        {'version': '10.1.0', 'lessThan': '10.1.14-h11'},
        {'version': '10.2.0', 'lessThan': '10.2.5'},
        {'version': '11.0.0', 'lessThan': '11.0.2'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if device is Cloud NGFW or Prisma Access (not vulnerable)
    model_match = re.search(r'model:\s*(\S+)', version_output)
    if model_match:
        model = model_match.group(1)
        if 'Prisma' in model or 'Cloud' in model:
            return

    # Check if GlobalProtect portal or gateway is configured
    # Look for GlobalProtect configuration in the running config
    config_str = str(configuration)
    
    has_globalprotect_portal = bool(re.search(r'globalprotect\s+portal', config_str, re.IGNORECASE))
    has_globalprotect_gateway = bool(re.search(r'globalprotect\s+gateway', config_str, re.IGNORECASE))
    
    # If GlobalProtect is not configured, device is not vulnerable
    if not has_globalprotect_portal and not has_globalprotect_gateway:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0114. "
        "The device is running a vulnerable version of PAN-OS with GlobalProtect enabled. "
        "An unauthenticated attacker can render the GlobalProtect service unavailable by sending "
        "a large number of specially crafted packets over a period of time. "
        "Upgrade to a fixed version: 10.1.14-h11+, 10.2.5+, or 11.0.2+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0114"
    )