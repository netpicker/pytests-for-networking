from comfy import high
import re


@high(
    name='rule_cve20254229',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_sdwan_interface_profile='show network sdwan-interface-profile',
    ),
)
def rule_cve20254229(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-4229 in PAN-OS configurations.
    The vulnerability is an information disclosure in the SD-WAN feature that enables 
    an unauthorized user to view unencrypted data sent from the firewall through the 
    SD-WAN interface when Direct Internet Access (DIA) is configured.
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
        {'version': '11.2.0', 'lessThan': '11.2.7'},
        {'version': '11.1.0', 'lessThan': '11.1.10'},
        {'version': '10.2.16', 'lessThan': '10.2.16-h1'},
        {'version': '10.2.0', 'lessThan': '10.2.16'},
        {'version': '10.1.0', 'lessThan': '10.1.14-h16'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SD-WAN Interface Profile is configured
    sdwan_output = commands.show_sdwan_interface_profile
    
    # Check if SD-WAN interface profiles exist
    has_sdwan_profile = False
    if sdwan_output and sdwan_output.strip():
        # If there's any output beyond headers/empty lines, SD-WAN profiles exist
        lines = [line.strip() for line in sdwan_output.split('\n') if line.strip()]
        # Filter out common header/empty response patterns
        if len(lines) > 0 and not all('No SD-WAN' in line or 'not configured' in line.lower() for line in lines):
            has_sdwan_profile = True
    
    # If no SD-WAN profile configured, device is not vulnerable
    if not has_sdwan_profile:
        return
    
    # Check configuration for SD-WAN with DIA
    config_str = str(configuration)
    
    # Look for SD-WAN interface profile configuration with DIA enabled
    has_dia_enabled = False
    
    # Check for direct-internet-access configuration in SD-WAN profiles
    if 'sdwan-interface-profile' in config_str.lower():
        # Look for direct-internet-access or dia configuration
        if 'direct-internet-access' in config_str.lower() or 'dia' in config_str.lower():
            # Check if it's enabled (not explicitly disabled)
            if 'direct-internet-access yes' in config_str.lower() or \
               ('direct-internet-access' in config_str.lower() and 'no' not in config_str.lower()):
                has_dia_enabled = True
    
    # If DIA is not enabled, device is not vulnerable
    if not has_dia_enabled:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-4229. "
        "The device is running a vulnerable version of PAN-OS with SD-WAN Interface Profile "
        "configured with Direct Internet Access (DIA) enabled. This allows an unauthorized user "
        "to view unencrypted data sent from the firewall through the SD-WAN interface. "
        "Upgrade to a fixed version: 11.2.7+, 11.1.10+, 10.2.16-h1+, 10.2.17+, or 10.1.14-h16+. "
        "Alternatively, disable Direct Internet Access by backhauling internet traffic to SD-WAN hub, "
        "or uninstall the SD-WAN plugin if not needed. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-4229"
    )