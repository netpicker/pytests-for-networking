from comfy import high
import re


@high(
    name='rule_cve20250130',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show running resource-monitor',
    ),
)
def rule_cve20250130(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0130 in PAN-OS configurations.
    The vulnerability allows an unauthenticated attacker to send a burst of maliciously crafted packets
    that causes the firewall to become unresponsive and eventually reboot when web proxy feature is enabled.
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
        """Check if device version is in vulnerable range"""
        device_norm = normalize_version(device_version)
        
        # PAN-OS 11.2: < 11.2.5 is vulnerable
        if device_norm >= (11, 2, 0, 0) and device_norm < (11, 2, 5, 0):
            return True
        
        # PAN-OS 11.1: < 11.1.6-h1, < 11.1.7-h2, < 11.1.8 is vulnerable
        if device_norm >= (11, 1, 0, 0) and device_norm < (11, 1, 6, 1):
            return True
        if device_norm >= (11, 1, 6, 1) and device_norm < (11, 1, 7, 0):
            return False
        if device_norm >= (11, 1, 7, 0) and device_norm < (11, 1, 7, 2):
            return True
        if device_norm >= (11, 1, 7, 2) and device_norm < (11, 1, 8, 0):
            return False
        if device_norm == (11, 1, 7, 2) or device_norm >= (11, 1, 8, 0):
            return False
        
        # PAN-OS 11.0 is EoL and vulnerable
        if device_norm >= (11, 0, 0, 0) and device_norm < (11, 1, 0, 0):
            return True
        
        # PAN-OS 10.2 and 10.1 are not affected
        if device_norm >= (10, 1, 0, 0) and device_norm < (11, 0, 0, 0):
            return False
            
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

    # Check if web proxy feature is enabled in configuration
    config_str = str(configuration)
    
    # Web proxy is configured under device config
    web_proxy_enabled = False
    if 'web-proxy' in config_str.lower():
        web_proxy_enabled = True
    
    # If web proxy is not enabled, device is not vulnerable
    if not web_proxy_enabled:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0130. "
        "The device is running a vulnerable version of PAN-OS with web proxy feature enabled. "
        "An unauthenticated attacker can send maliciously crafted packets causing DoS and reboot. "
        "Upgrade to a fixed version: 11.2.5+, 11.1.6-h1+, 11.1.7-h2+, or 11.1.8+. "
        "Alternatively, disable the web proxy feature if not in use. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0130"
    )