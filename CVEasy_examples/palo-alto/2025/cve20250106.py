from comfy import high
import re


@high(
    name='rule_cve20250106',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20250106(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0106 in Expedition configurations.
    A wildcard expansion vulnerability in Palo Alto Networks Expedition allows an unauthenticated 
    attacker to enumerate files on the host filesystem.
    
    Note: This vulnerability affects Expedition, not PAN-OS firewalls, Panorama, Prisma Access, 
    or Cloud NGFW. This rule checks if the device is running Expedition software.
    """
    # Extract system info
    system_info = commands.show_system_info
    
    def normalize_version(version_str: str) -> tuple:
        """Parse version string into comparable tuple"""
        match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_str)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            return (major, minor, patch)
        return (0, 0, 0)
    
    def is_expedition_version_affected(device_version: str) -> bool:
        """Check if Expedition version is vulnerable to CVE-2025-0106"""
        device_norm = normalize_version(device_version)
        # Vulnerable: Expedition 1 < 1.2.101
        # Fixed: Expedition >= 1.2.101
        fixed_version = (1, 2, 101)
        
        if device_norm < fixed_version:
            return True
        return False

    # Check if this is an Expedition system
    # Expedition would have specific identifiers in system info
    if 'expedition' not in system_info.lower():
        # This is not an Expedition system, rule does not apply
        return

    # Extract version from system info
    version_match = re.search(r'(?:sw-version|version):\s*(\d+\.\d+\.\d+)', system_info, re.IGNORECASE)
    if not version_match:
        return
    
    version = version_match.group(1)
    
    # Check if version is vulnerable
    version_vulnerable = is_expedition_version_affected(version)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0106. "
        "The Expedition system is running a vulnerable version that allows unauthenticated attackers "
        "to enumerate files on the host filesystem through wildcard expansion. "
        "Upgrade to Expedition 1.2.101 or later. "
        "Note: Expedition reached End of Life on December 31, 2024. Consider using alternative migration tools. "
        "Ensure network access to Expedition is restricted to authorized users only. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0106"
    )