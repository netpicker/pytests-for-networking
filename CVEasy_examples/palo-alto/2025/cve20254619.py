from comfy import high
import re


@high(
    name='rule_cve20254619',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_config='show config running',
    ),
)
def rule_cve20254619(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-4619 in PAN-OS configurations.
    A denial-of-service (DoS) vulnerability in Palo Alto Networks PAN-OS software enables 
    an unauthenticated attacker to reboot a firewall by sending a specially crafted packet 
    through the dataplane. Repeated attempts to initiate a reboot causes the firewall to 
    enter maintenance mode.
    
    This issue is only applicable to firewalls where URL proxy or any decrypt-policy is configured.
    """
    # Extract system info
    version_output = commands.show_system_info
    config_output = commands.show_config
    
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
    
    # Define version ranges for vulnerable versions based on CVE advisory
    vulnerable_version_ranges = [
        # PAN-OS 11.2
        {'version': '11.2.0', 'lessThan': '11.2.2-h2'},
        {'version': '11.2.2', 'lessThan': '11.2.2-h2'},
        {'version': '11.2.3', 'lessThan': '11.2.3-h6'},
        {'version': '11.2.4', 'lessThan': '11.2.4-h4'},
        # PAN-OS 11.1
        {'version': '11.1.2-h9', 'lessThan': '11.1.2-h18'},
        {'version': '11.1.3-h2', 'lessThan': '11.1.4-h4'},
        {'version': '11.1.4-h4', 'lessThan': '11.1.4-h13'},
        {'version': '11.1.6', 'lessThan': '11.1.6-h1'},
        # PAN-OS 10.2
        {'version': '10.2.4-h25', 'lessThan': '10.2.7-h11'},
        {'version': '10.2.7-h11', 'lessThan': '10.2.7-h24'},
        {'version': '10.2.8-h10', 'lessThan': '10.2.8-h21'},
        {'version': '10.2.9-h6', 'lessThan': '10.2.9-h21'},
        {'version': '10.2.10-h2', 'lessThan': '10.2.10-h14'},
        {'version': '10.2.11', 'lessThan': '10.2.11-h12'},
        {'version': '10.2.12', 'lessThan': '10.2.12-h6'},
        {'version': '10.2.13', 'lessThan': '10.2.13-h3'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if URL proxy is enabled
    url_proxy_enabled = False
    if re.search(r'url-proxy\s+yes', config_output):
        url_proxy_enabled = True
    
    # Check if any decrypt policy is configured
    decrypt_policy_configured = False
    if re.search(r'decrypt-policy|decryption\s+rule', config_output, re.IGNORECASE):
        decrypt_policy_configured = True
    
    # Device is only vulnerable if URL proxy OR decrypt policy is configured
    if not (url_proxy_enabled or decrypt_policy_configured):
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-4619. "
        "The device is running a vulnerable version of PAN-OS that allows an unauthenticated "
        "attacker to reboot the firewall by sending a specially crafted packet through the dataplane. "
        f"Current version: {version}. "
        "Vulnerable configuration detected: URL proxy or decrypt policy is enabled. "
        "Upgrade to a fixed version: 11.2.5+, 11.2.4-h4+, 11.2.3-h6+, 11.2.2-h2+, "
        "11.1.7+, 11.1.6-h1+, 11.1.4-h13+, 10.2.14+, or appropriate hotfix. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-4619"
    )