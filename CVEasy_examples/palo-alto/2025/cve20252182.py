from comfy import high
import re


@high(
    name='rule_cve20252182',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_high_availability_state='show high-availability state',
        show_running_config='show running high-availability',
    ),
)
def rule_cve20252182(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-2182 in PA-7500 Series devices.
    The vulnerability exposes the connectivity association key (CAK) in cleartext when MACsec 
    protocol is used in NGFW clusters on PA-7500 Series devices.
    """
    # Extract system info
    version_output = commands.show_system_info
    ha_state_output = commands.show_high_availability_state
    ha_config_output = commands.show_running_config
    
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
    
    # Extract model from system info
    model_match = re.search(r'model:\s*(\S+)', version_output)
    if not model_match:
        return
    
    model = model_match.group(1)
    
    # Check if device is PA-7500 Series
    if not model.startswith('PA-7500'):
        return
    
    # Define version ranges for vulnerable versions on PA-7500
    vulnerable_version_ranges = [
        {'version': '11.2.0', 'lessThan': '11.2.8'},
        {'version': '11.1.0', 'lessThan': '11.1.10'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if device is in an NGFW cluster
    is_clustered = False
    if re.search(r'(cluster|ha-mode:\s*active-active)', ha_state_output, re.IGNORECASE):
        is_clustered = True
    
    # If not clustered, device is not vulnerable
    if not is_clustered:
        return
    
    # Check if MACsec is configured and enabled
    macsec_enabled = False
    if re.search(r'macsec', ha_config_output, re.IGNORECASE):
        macsec_enabled = True
    
    # If MACsec is not enabled, device is not vulnerable
    if not macsec_enabled:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-2182. "
        "The PA-7500 Series device is running a vulnerable version of PAN-OS in an NGFW cluster "
        "with MACsec enabled, which results in cleartext exposure of the connectivity association key (CAK). "
        "An attacker with this key can read messages being sent between devices in the NGFW Cluster. "
        "Upgrade to a fixed version: 11.2.8+ or 11.1.10+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-2182"
    )