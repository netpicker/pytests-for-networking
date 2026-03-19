from comfy import high
import re


@high(
    name='rule_cve20250136',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_ipsec_crypto='show running network-config ipsec-crypto',
    ),
)
def rule_cve20250136(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0136 in PAN-OS configurations.
    The vulnerability causes unencrypted data transfer when using AES-128-CCM algorithm for IPSec 
    on certain Intel-based hardware firewalls (PA-7500, PA-5400, PA-5400f, PA-3400, PA-1600, PA-1400, PA-400 Series).
    """
    # Extract system info
    version_output = commands.show_system_info
    ipsec_config = commands.show_ipsec_crypto
    
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
    
    # Check if device is an affected hardware model (Intel-based x86_64 platforms)
    affected_models = ['PA-7500', 'PA-5400', 'PA-5400f', 'PA-3400', 'PA-1600', 'PA-1400', 'PA-400']
    is_affected_hardware = any(model.startswith(affected_model.replace('f', '')) for affected_model in affected_models)
    
    # VM-Series, Cloud NGFW, and Prisma Access are not affected
    if model.startswith('PA-VM') or 'Prisma' in version_output or 'Cloud' in version_output:
        return
    
    # Define version ranges for vulnerable versions
    vulnerable_version_ranges = [
        {'version': '10.1.0', 'lessThan': '10.1.14-h14'},
        {'version': '10.2.0', 'lessThan': '10.2.11'},
        {'version': '11.0.0', 'lessThan': '11.0.7'},
        {'version': '11.1.0', 'lessThan': '11.1.5'},
    ]
    
    # Check if version is vulnerable
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
    
    # If not affected hardware, no need to check further
    if not is_affected_hardware:
        return

    # Check if AES-128-CCM is configured in IPSec Crypto profiles
    aes_128_ccm_configured = bool(re.search(r'aes-128-ccm|aes128ccm|AES-128-CCM', ipsec_config, re.IGNORECASE))

    # If AES-128-CCM is not configured, device is not vulnerable
    if not aes_128_ccm_configured:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0136. "
        "The device is running a vulnerable version of PAN-OS on Intel-based hardware with AES-128-CCM "
        "configured for IPSec, which leads to unencrypted data transfer. "
        "Upgrade to a fixed version: 10.1.14-h14+, 10.2.11+, 11.0.7+, 11.1.5+, or 11.2+. "
        "Alternatively, configure IPSec Crypto encryption to use AES-256-GCM or AES-256-CBC instead. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0136"
    )