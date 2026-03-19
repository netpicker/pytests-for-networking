from comfy import high
import re


@high(
    name='rule_cve20250133',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show running resource-monitor',
    ),
)
def rule_cve20250133(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0133 in PAN-OS configurations.
    A reflected cross-site scripting (XSS) vulnerability in the GlobalProtect gateway and portal features
    enables execution of malicious JavaScript in the context of an authenticated Captive Portal user's browser.
    The primary risk is phishing attacks that can lead to credential theft—particularly if Clientless VPN is enabled.
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
        {'version': '10.1.0', 'lessThan': '10.2.16-h1'},
        {'version': '10.2.0', 'lessThan': '10.2.16-h1'},
        {'version': '11.1.0', 'lessThan': '11.1.6-h14'},
        {'version': '11.1.6', 'lessThan': '11.1.6-h14'},
        {'version': '11.1.7', 'lessThan': '11.1.10-h1'},
        {'version': '11.2.0', 'lessThan': '11.2.4-h9'},
        {'version': '11.2.4', 'lessThan': '11.2.4-h9'},
        {'version': '11.2.5', 'lessThan': '11.2.7'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if GlobalProtect gateway or portal is enabled
    config_text = str(configuration)
    
    # Look for GlobalProtect gateway or portal configuration
    globalprotect_gateway_enabled = bool(
        re.search(r'set\s+network\s+global-protect\s+gateway', config_text, re.IGNORECASE) or
        re.search(r'gateway\s+{', config_text, re.IGNORECASE)
    )
    
    globalprotect_portal_enabled = bool(
        re.search(r'set\s+network\s+global-protect\s+portal', config_text, re.IGNORECASE) or
        re.search(r'portal\s+{', config_text, re.IGNORECASE)
    )
    
    # If neither GlobalProtect gateway nor portal is enabled, device is not vulnerable
    if not globalprotect_gateway_enabled and not globalprotect_portal_enabled:
        return

    # Check if Clientless VPN is enabled (increases severity)
    clientless_vpn_enabled = bool(
        re.search(r'clientless-vpn\s+enable\s+yes', config_text, re.IGNORECASE) or
        re.search(r'enable-clientless-vpn\s+yes', config_text, re.IGNORECASE)
    )

    # Build vulnerability message
    severity = "MEDIUM" if clientless_vpn_enabled else "LOW"
    clientless_note = (
        " Clientless VPN is enabled, which increases the risk of credential theft. "
        "Consider disabling Clientless VPN to reduce impact. "
    ) if clientless_vpn_enabled else ""
    
    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0133 (Severity: {severity}). "
        "A reflected XSS vulnerability in GlobalProtect gateway/portal enables execution of malicious JavaScript "
        "in the context of an authenticated Captive Portal user's browser. "
        f"{clientless_note}"
        "Mitigation: Enable Threat Prevention with Threat IDs 510003 and 510004 (content version 8995+) "
        "and apply Vulnerability Protection profiles to GlobalProtect interfaces. "
        "Upgrade to a fixed version: 10.2.16-h1+, 11.1.6-h14+, 11.1.10-h1+, 11.2.4-h9+, or 11.2.7+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0133"
    )