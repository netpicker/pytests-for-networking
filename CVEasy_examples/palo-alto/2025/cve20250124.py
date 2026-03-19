from comfy import high
import re


@high(
    name='rule_cve20250124',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_management_interface='show running resource-monitor ingress-backlogs | match "Management"',
    ),
)
def rule_cve20250124(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0124 in PAN-OS configurations.
    The vulnerability allows an authenticated attacker with network access to the management web interface
    to delete certain files as the "nobody" user; this includes limited logs and configuration files
    but does not include system files.
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
        {'version': '10.2.0', 'lessThan': '10.2.10'},
        {'version': '11.0.0', 'lessThan': '11.0.6'},
        {'version': '11.1.0', 'lessThan': '11.1.5'},
        {'version': '11.2.0', 'lessThan': '11.2.1'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if management interface is exposed
    # Look for management interface configuration that allows external access
    config_str = str(configuration)
    
    # Check for management profile on dataplane interfaces
    management_profile_exposed = False
    if re.search(r'set\s+network\s+interface\s+ethernet\s+\S+\s+layer3.*management-profile', config_str, re.IGNORECASE):
        management_profile_exposed = True
    
    # Check for permitted-ip configuration - if it exists and restricts to internal IPs, it's safer
    has_ip_restrictions = False
    if re.search(r'set\s+deviceconfig\s+system\s+permitted-ip', config_str, re.IGNORECASE):
        # Check if restrictions are in place (presence of permitted-ip suggests restrictions)
        has_ip_restrictions = True
    
    # Check for service route configuration that might expose management
    service_route_exposed = False
    if re.search(r'set\s+deviceconfig\s+system\s+service.*source-interface', config_str, re.IGNORECASE):
        service_route_exposed = True

    # Device is vulnerable if:
    # 1. Version is vulnerable AND
    # 2. Management interface is potentially exposed (management profile on dataplane OR no IP restrictions)
    is_vulnerable = version_vulnerable and (management_profile_exposed or not has_ip_restrictions)

    # Assert that the device is not vulnerable
    if is_vulnerable:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-0124. "
            "The device is running a vulnerable version of PAN-OS that allows authenticated attackers "
            "to delete certain files through the management web interface. "
            "Upgrade to a fixed version: 10.1.14-h11+, 10.2.10+, 11.0.6+, 11.1.5+, or 11.2.1+. "
            "Additionally, restrict management interface access to only trusted internal IP addresses. "
            "For more details see: https://security.paloaltonetworks.com/CVE-2025-0124"
        )