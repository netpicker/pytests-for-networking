from comfy import high
import re


@high(
    name='rule_cve20250107',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20250107(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0107 in Expedition configurations.
    An OS command injection vulnerability in Palo Alto Networks Expedition enables an unauthenticated 
    attacker to run arbitrary OS commands as the www-data user in Expedition, which results in the 
    disclosure of usernames, cleartext passwords, device configurations, and device API keys for 
    firewalls running PAN-OS software.
    
    Note: This vulnerability affects Expedition, not PAN-OS firewalls directly. However, we check
    if the device is running Expedition software.
    """
    # Extract system info
    system_info = commands.show_system_info
    
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
    
    def is_expedition_version_affected(device_version: str) -> bool:
        """Check if Expedition version is vulnerable to CVE-2025-0107"""
        device_norm = normalize_version(device_version)
        # Vulnerable: Expedition < 1.2.100
        fixed_version = normalize_version('1.2.100')
        
        # Check if this is Expedition version 1.x
        if device_norm[0] == 1 and device_norm < fixed_version:
            return True
                
        return False

    # Check if this is an Expedition system
    # Expedition would be identified differently than standard PAN-OS
    is_expedition = False
    
    # Look for Expedition-specific indicators in system info
    if 'expedition' in system_info.lower() or 'migration tool' in system_info.lower():
        is_expedition = True
    
    # If not Expedition, this CVE doesn't apply
    if not is_expedition:
        return
    
    # Extract version from sw-version line
    version_match = re.search(r'sw-version:\s*(\S+)', system_info)
    if not version_match:
        # Try alternative version pattern for Expedition
        version_match = re.search(r'version:\s*(\S+)', system_info)
        if not version_match:
            return
    
    version = version_match.group(1)
    
    # Check if Expedition version is vulnerable
    version_vulnerable = is_expedition_version_affected(version)

    # If version is not vulnerable, device is safe
    if not version_vulnerable:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0107. "
        "The Expedition migration tool is running a vulnerable version that allows unauthenticated "
        "OS command injection, enabling attackers to run arbitrary OS commands as the www-data user. "
        "This results in disclosure of usernames, cleartext passwords, device configurations, and "
        "device API keys for firewalls running PAN-OS software. "
        "Upgrade Expedition to version 1.2.100 or later. "
        "Note: Expedition reached End of Life on December 31, 2024. Consider using alternative migration tools. "
        "Ensure network access to Expedition is restricted to authorized users only. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0107"
    )