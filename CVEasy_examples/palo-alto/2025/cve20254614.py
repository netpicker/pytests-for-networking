from comfy import high
import re


@high(
    name='rule_cve20254614',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20254614(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-4614 in PAN-OS configurations.
    The vulnerability allows an authenticated administrator to view session tokens of users 
    authenticated to the firewall web UI, potentially enabling impersonation.
    
    Required configuration for exposure: The debug option must be enabled on the URL:
    https://<ip>/php/utils/debug.php
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
        {'version': '10.2.0', 'lessThan': '10.2.17'},
        {'version': '11.1.0', 'lessThan': '11.1.6-h21'},
        {'version': '11.2.0', 'lessThan': '11.2.8'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if this is Cloud NGFW or Prisma Access (not affected)
    model_match = re.search(r'model:\s*(\S+)', version_output)
    if model_match:
        model = model_match.group(1)
        if 'Prisma' in model or 'Cloud' in model:
            return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-4614. "
        "The device is running a vulnerable version of PAN-OS that allows authenticated administrators "
        "to view session tokens of users authenticated to the firewall web UI when the debug option is enabled. "
        "This may allow impersonation of users whose session tokens are leaked. "
        "Upgrade to a fixed version: 10.2.17+, 11.1.6-h21+, 11.2.8+, or 12.1+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-4614"
    )