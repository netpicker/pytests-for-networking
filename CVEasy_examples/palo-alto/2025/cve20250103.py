from comfy import high
import re


@high(
    name='rule_cve20250103',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20250103(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0103 in Expedition configurations.
    An SQL injection vulnerability in Palo Alto Networks Expedition enables an authenticated attacker 
    to reveal Expedition database contents, such as password hashes, usernames, device configurations, 
    and device API keys. This vulnerability also enables attackers to create and read arbitrary files 
    on the Expedition system.
    
    Note: This vulnerability affects Expedition, not PAN-OS firewalls directly. However, Expedition
    can expose firewall credentials and configurations.
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
    
    def is_expedition_version_affected(device_version: str) -> bool:
        """Check if Expedition version is vulnerable to CVE-2025-0103"""
        device_norm = normalize_version(device_version)
        # Vulnerable: Expedition 1.x < 1.2.100
        fixed_version = normalize_version('1.2.100')
        expedition_base = normalize_version('1.0.0')
        
        if expedition_base <= device_norm < fixed_version:
            return True
        return False

    # Check if this is an Expedition system
    if 'expedition' not in version_output.lower() and 'migration tool' not in version_output.lower():
        # This is not an Expedition system, vulnerability does not apply
        return
    
    # Extract version from sw-version or version line
    version_match = re.search(r'(?:sw-version|version):\s*(\S+)', version_output, re.IGNORECASE)
    if not version_match:
        return
    
    version = version_match.group(1)
    
    # Check if Expedition version is vulnerable
    version_vulnerable = is_expedition_version_affected(version)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Expedition system {device.name} is vulnerable to CVE-2025-0103. "
        f"Running vulnerable Expedition version {version} (< 1.2.100). "
        "This SQL injection vulnerability enables authenticated attackers to reveal Expedition database contents "
        "including password hashes, usernames, device configurations, and device API keys. "
        "Attackers can also create and read arbitrary files on the Expedition system. "
        "Upgrade to Expedition 1.2.100 or later. "
        "Note: Expedition reached End of Life on December 31, 2024. Consider using alternative migration tools. "
        "Ensure network access to Expedition is restricted to authorized users only. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0103"
    )