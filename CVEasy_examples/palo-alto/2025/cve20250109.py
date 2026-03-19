from comfy import high
import re


@high(
    name='rule_cve20250109',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20250109(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0109 in PAN-OS configurations.
    An unauthenticated file deletion vulnerability in the Palo Alto Networks PAN-OS management 
    web interface enables an unauthenticated attacker with network access to the management web 
    interface to delete certain files as the "nobody" user; this includes limited logs and 
    configuration files but does not include system files.
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
    
    # Define version ranges for vulnerable versions based on CVE-2025-0109
    vulnerable_version_ranges = [
        {'version': '9.0.0', 'lessThan': '9.0.18'},
        {'version': '9.1.0', 'lessThan': '9.1.20'},
        {'version': '10.1.0', 'lessThan': '10.1.15'},
        {'version': '10.2.0', 'lessThan': '10.2.13'},
        {'version': '11.0.0', 'lessThan': '11.0.7'},
        {'version': '11.1.0', 'lessThan': '11.1.5'},
        {'version': '11.2.0', 'lessThan': '11.2.4'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if this is Cloud NGFW or Prisma Access (not affected)
    config = commands.show_system_info
    if 'cloud-mode: cloud' in config.lower() or 'prisma-access' in config.lower():
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0109. "
        "The device is running a vulnerable version of PAN-OS with an unauthenticated file deletion "
        "vulnerability in the management web interface. An unauthenticated attacker with network access "
        "to the management web interface can delete certain files as the 'nobody' user. "
        "Upgrade to a fixed version: 9.0.18+, 9.1.20+, 10.1.15+, 10.2.13+, 11.0.7+, 11.1.5+, 11.2.4+, or 11.3+. "
        "Restrict access to the management web interface to only trusted internal IP addresses. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0109"
    )