from comfy import high
import re


@high(
    name='rule_cve20254230',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20254230(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-4230 in PAN-OS configurations.
    A command injection vulnerability in Palo Alto Networks PAN-OS software enables an authenticated 
    administrator to bypass system restrictions and run arbitrary commands as a root user. 
    To be able to exploit this issue, the user must have access to the PAN-OS CLI.
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
    
    # Check if this is Cloud NGFW or Prisma Access (not affected)
    model_match = re.search(r'model:\s*(\S+)', version_output)
    if model_match:
        model = model_match.group(1)
        if 'Prisma' in model or 'Cloud-NGFW' in model:
            return
    
    # Define version ranges for vulnerable versions.
    # The 11.1 train has a hotfix boundary: 11.1.0..11.1.6 is fully vulnerable,
    # 11.1.6-hN is vulnerable only for N < 14, and 11.1.7..11.1.9 is vulnerable.
    # Split into non-overlapping ranges to avoid catching 11.1.6-h14+ as vulnerable.
    vulnerable_version_ranges = [
        {'version': '11.2.0', 'lessThan': '11.2.6'},
        {'version': '11.1.0', 'lessThan': '11.1.6'},
        {'version': '11.1.6', 'lessThan': '11.1.6-h14'},
        {'version': '11.1.7', 'lessThan': '11.1.10'},
        {'version': '10.2.0', 'lessThan': '10.2.10-h27'},
        {'version': '10.1.0', 'lessThan': '10.1.14-h15'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-4230. "
        "The device is running a vulnerable version of PAN-OS that allows authenticated administrators "
        "with CLI access to bypass system restrictions and run arbitrary commands as root. "
        "Upgrade to a fixed version: 11.2.6+, 11.1.6-h14+, 11.1.10+, 10.2.10-h27+, or 10.1.14-h15+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-4230"
    )