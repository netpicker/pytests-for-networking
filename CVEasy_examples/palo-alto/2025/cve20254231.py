from comfy import high
import re


@high(
    name='rule_cve20254231',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_config='show config running',
    ),
)
def rule_cve20254231(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-4231 in PAN-OS configurations.
    A command injection vulnerability in Palo Alto Networks PAN-OS enables an authenticated 
    administrative user to perform actions as the root user. The attacker must have network 
    access to the management web interface and successfully authenticate to exploit this issue.
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
    
    # Define version ranges for vulnerable versions
    # PAN-OS 11.0: 11.0.0 through 11.0.2 (fixed in 11.0.3)
    # PAN-OS 10.2: 10.2.0 through 10.2.7 (fixed in 10.2.8)
    # PAN-OS 10.1: All versions
    vulnerable_version_ranges = [
        {'version': '10.1.0', 'lessThan': '10.2.0'},
        {'version': '10.2.0', 'lessThan': '10.2.8'},
        {'version': '11.0.0', 'lessThan': '11.0.3'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if management interface is exposed
    # Look for management interface configuration that could expose the device
    # The vulnerability requires network access to the management web interface
    
    # Check for management profile on dataplane interfaces
    has_mgmt_profile = bool(re.search(r'set\s+network\s+interface\s+ethernet\s+\S+\s+layer3\s+interface-management-profile', config_output))
    
    # Check for permitted-ip configuration (if no permitted-ip is set, it's more exposed)
    has_permitted_ip = bool(re.search(r'set\s+deviceconfig\s+system\s+permitted-ip', config_output))
    
    # Check for service-https or service-http enabled
    has_https_service = bool(re.search(r'set\s+deviceconfig\s+system\s+service\s+disable-https\s+no', config_output)) or \
                       not bool(re.search(r'set\s+deviceconfig\s+system\s+service\s+disable-https\s+yes', config_output))
    
    # Device is considered vulnerable if:
    # 1. Version is vulnerable AND
    # 2. Management interface is accessible (has management profile OR https service is enabled)
    # 3. No IP restrictions are in place (no permitted-ip configured)
    
    # If management profile exists on dataplane or https is enabled without IP restrictions, it's vulnerable
    is_exposed = (has_mgmt_profile or has_https_service) and not has_permitted_ip
    
    if is_exposed:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-4231. "
            "The device is running a vulnerable version of PAN-OS with an exposed management interface. "
            "A command injection vulnerability enables an authenticated administrative user to perform actions as root. "
            "Mitigation: Restrict management interface access to trusted internal IP addresses only. "
            "Upgrade to a fixed version: 10.2.8+, 11.0.3+, or later. "
            "For more details see: https://security.paloaltonetworks.com/CVE-2025-4231"
        )