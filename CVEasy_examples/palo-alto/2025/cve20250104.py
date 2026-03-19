from comfy import high
import re


@high(
    name='rule_cve20250104',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20250104(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0104 in Expedition configurations.
    A reflected cross-site scripting (XSS) vulnerability in Palo Alto Networks Expedition 
    enables attackers to execute malicious JavaScript code in the context of an authenticated 
    Expedition user's browser if that authenticated user clicks a malicious link that allows 
    phishing attacks and could lead to Expedition browser-session theft.
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
        """Check if Expedition version is vulnerable to CVE-2025-0104"""
        device_norm = normalize_version(device_version)
        # Vulnerable: Expedition 1.x < 1.2.100
        # Fixed in: Expedition 1.2.100 and later
        
        if device_norm[0] == 1:
            # Check if version is less than 1.2.100
            if device_norm < (1, 2, 100, 0):
                return True
        
        return False

    # Check if this is an Expedition system
    if 'expedition' not in version_output.lower() and 'model: expedition' not in version_output.lower():
        # This is not an Expedition system, CVE does not apply
        return

    # Extract version from sw-version or app-version line
    version_match = re.search(r'(?:sw-version|app-version|version):\s*(\S+)', version_output, re.IGNORECASE)
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
        f"Device {device.name} is vulnerable to CVE-2025-0104. "
        "The Expedition system is running a vulnerable version that allows reflected XSS attacks. "
        "An attacker can execute malicious JavaScript code in the context of an authenticated user's browser "
        "if the user clicks a malicious link, which could lead to phishing attacks and browser-session theft. "
        "Upgrade to Expedition 1.2.100 or later. "
        "Note: Expedition reached End of Life on December 31, 2024. Consider using suggested alternatives. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0104"
    )