from comfy import high
import re


@high(
    name='rule_cve20250111',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_management_interface='show running resource-monitor second last 1',
    ),
)
def rule_cve20250111(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0111 in PAN-OS configurations.
    An authenticated file read vulnerability in the management web interface enables an authenticated 
    attacker with network access to the management web interface to read files on the PAN-OS filesystem 
    that are readable by the "nobody" user.
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
    
    def is_version_affected(device_version: str) -> bool:
        """Check if device version is vulnerable"""
        device_norm = normalize_version(device_version)
        
        # PAN-OS 10.1: < 10.1.14-h9
        if device_norm >= (10, 1, 0, 0) and device_norm < (10, 1, 14, 9):
            return True
        
        # PAN-OS 10.2: < 10.2.7-h24, < 10.2.8-h21, < 10.2.9-h21, < 10.2.10-h14, < 10.2.11-h12, < 10.2.12-h6, < 10.2.13-h3
        if device_norm >= (10, 2, 0, 0) and device_norm < (10, 2, 7, 0):
            return True
        if device_norm >= (10, 2, 7, 0) and device_norm < (10, 2, 7, 24):
            return True
        if device_norm >= (10, 2, 8, 0) and device_norm < (10, 2, 8, 21):
            return True
        if device_norm >= (10, 2, 9, 0) and device_norm < (10, 2, 9, 21):
            return True
        if device_norm >= (10, 2, 10, 0) and device_norm < (10, 2, 10, 14):
            return True
        if device_norm >= (10, 2, 11, 0) and device_norm < (10, 2, 11, 12):
            return True
        if device_norm >= (10, 2, 12, 0) and device_norm < (10, 2, 12, 6):
            return True
        if device_norm >= (10, 2, 13, 0) and device_norm < (10, 2, 13, 3):
            return True
        
        # PAN-OS 11.1: < 11.1.2-h18, < 11.1.4-h13, < 11.1.6-h1
        if device_norm >= (11, 1, 0, 0) and device_norm < (11, 1, 2, 0):
            return True
        if device_norm >= (11, 1, 2, 0) and device_norm < (11, 1, 2, 18):
            return True
        if device_norm >= (11, 1, 3, 0) and device_norm < (11, 1, 4, 0):
            return True
        if device_norm >= (11, 1, 4, 0) and device_norm < (11, 1, 4, 13):
            return True
        if device_norm >= (11, 1, 5, 0) and device_norm < (11, 1, 6, 0):
            return True
        if device_norm >= (11, 1, 6, 0) and device_norm < (11, 1, 6, 1):
            return True
        
        # PAN-OS 11.2: < 11.2.4-h4, < 11.2.5
        if device_norm >= (11, 2, 0, 0) and device_norm < (11, 2, 4, 0):
            return True
        if device_norm >= (11, 2, 4, 0) and device_norm < (11, 2, 4, 4):
            return True
        if device_norm >= (11, 2, 4, 4) and device_norm < (11, 2, 5, 0):
            return True
        
        # PAN-OS 11.0 and older (EoL) - presumed affected
        if device_norm >= (9, 0, 0, 0) and device_norm < (10, 1, 0, 0):
            return True
        
        return False

    # Extract version from sw-version line
    version_match = re.search(r'sw-version:\s*(\S+)', version_output)
    if not version_match:
        return
    
    version = version_match.group(1)
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if management interface is exposed
    # Look for management interface configuration in the device configuration
    config_str = str(configuration)
    
    # Check for management profile on dataplane interfaces
    management_profile_exposed = False
    if 'management-profile' in config_str.lower():
        # If management profile is configured on dataplane interfaces, it's potentially exposed
        management_profile_exposed = True
    
    # Check if device is Panorama (not vulnerable) or Cloud NGFW/Prisma Access (not vulnerable)
    model_match = re.search(r'model:\s*(\S+)', version_output)
    if model_match:
        model = model_match.group(1)
        if 'Panorama' in model or 'M-' in model:
            # Panorama devices are also vulnerable
            pass

    # The vulnerability requires network access to management web interface
    # If we can't determine exposure from config, we assume it's potentially vulnerable
    # since the advisory states the attacker must have network access to exploit
    
    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0111. "
        f"Running version {version} is affected by an authenticated file read vulnerability "
        "in the management web interface that allows authenticated attackers with network access "
        "to read files on the PAN-OS filesystem readable by the 'nobody' user. "
        "Restrict management interface access to trusted internal IP addresses only. "
        "Upgrade to a fixed version: 10.1.14-h9+, 10.2.7-h24+, 10.2.8-h21+, 10.2.9-h21+, "
        "10.2.10-h14+, 10.2.11-h12+, 10.2.12-h6+, 10.2.13-h3+, 11.1.2-h18+, 11.1.4-h13+, "
        "11.1.6-h1+, 11.2.4-h4+, or 11.2.5+. "
        "Enable Threat Prevention Threat ID 510000 and 510001 (content version 8943+). "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0111"
    )