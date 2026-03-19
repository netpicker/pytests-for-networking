from comfy import high
import re


@high(
    name='rule_cve20250123',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_config_http2='show config running | match "http2 enable no"',
        show_config_decryption='show config running | match "strip-alpn"',
    ),
)
def rule_cve20250123(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0123 in PAN-OS configurations.
    The vulnerability enables unlicensed administrators to view clear-text data captured using 
    the packet capture feature in decrypted HTTP/2 data streams traversing network interfaces 
    on the firewall. HTTP/1.1 data streams are not impacted.
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
        {'version': '11.2.0', 'lessThan': '11.2.6'},
        {'version': '11.1.0', 'lessThan': '11.1.8'},
        {'version': '11.1.6', 'lessThan': '11.1.6-h10'},
        {'version': '10.2.0', 'lessThan': '10.2.15'},
        {'version': '10.2.10', 'lessThan': '10.2.10-h21'},
        {'version': '10.1.0', 'lessThan': '10.1.14-h13'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if HTTP/2 is globally disabled
    http2_config = commands.show_config_http2
    http2_disabled = 'http2 enable no' in http2_config
    
    # If HTTP/2 is disabled, the device is not vulnerable
    if http2_disabled:
        return
    
    # Check if strip-alpn is enabled in decryption profiles
    decryption_config = commands.show_config_decryption
    strip_alpn_enabled = 'strip-alpn yes' in decryption_config
    
    # If strip-alpn is enabled, the device is not vulnerable
    if strip_alpn_enabled:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0123. "
        "The device is running a vulnerable version of PAN-OS that allows unlicensed administrators "
        "to view clear-text data in decrypted HTTP/2 packet captures. "
        "Mitigation options: (1) Upgrade to a fixed version: 11.2.6+, 11.1.8+, 11.1.6-h10+, "
        "10.2.15+, 10.2.10-h21+, or 10.1.14-h13+; "
        "(2) Configure decryption profiles to strip ALPN; "
        "(3) Globally disable HTTP/2 inspection via CLI. "
        "After upgrading, delete all pre-existing packet capture files. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0123"
    )