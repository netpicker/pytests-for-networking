from comfy import high


@high(
    name='rule_cve20240007',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20240007(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-0007 in PAN-OS Panorama appliances.
    The vulnerability allows a malicious authenticated read-write administrator to store
    a JavaScript payload using the web interface, enabling impersonation of another
    authenticated administrator.
    
    Fixed versions:
    - PAN-OS 8.1.24-h1 and later
    - PAN-OS 9.0.17 and later
    - PAN-OS 9.1.16 and later
    - PAN-OS 10.0.11 and later
    - PAN-OS 10.1.6 and later
    - PAN-OS 10.2.0 and later
    """
    # Extract system info
    system_info = commands.show_system_info
    
    # Check if this is a Panorama device
    if 'model: PA' not in system_info:
        return
        
    def is_version_affected(device_version: str, versions: list) -> bool:
        """
        Check if a device version is affected by comparing it against version ranges.
        
        Args:
            device_version: Device version string to check
            versions: List of dicts containing version ranges with 'version' and 'lessThan' keys
        
        Returns:
            bool: True if the version is affected, False otherwise
        """
        # Assuming normalized_cve_version is a separate function that normalizes version strings
        device_norm = normalized_cve_version(device_version)
        
        for version_range in versions:
            base_version = normalized_cve_version(version_range['version'])
            cap_version = normalized_cve_version(version_range['lessThan'])
            
            if base_version <= device_norm < cap_version:
                return True
                
        return False

    # Extract version information
    version = commands.show_system_info
    
    # Define version ranges for vulnerable versions
    vulnerable_version_ranges = [
        {'version': '8.1.0', 'lessThan': '8.1.24-h1'},
        {'version': '9.0.0', 'lessThan': '9.0.17'},
        {'version': '9.1.0', 'lessThan': '9.1.16'},
        {'version': '10.0.0', 'lessThan': '10.0.11'},
        {'version': '10.1.0', 'lessThan': '10.1.6'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-0007. "
        "The Panorama appliance is running a vulnerable version which is susceptible to stored XSS attacks. "
        "This could allow a malicious read-write administrator to impersonate other administrators. "
        "Upgrade to a fixed version: 8.1.24-h1+, 9.0.17+, 9.1.16+, 10.0.11+, 10.1.6+ or 10.2.0+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-0007"
    )
