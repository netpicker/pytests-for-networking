from comfy import high
import re


@high(
    name='rule_cve20250128',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_scep_status='debug sslmgr show disable-scep-auth-cookie',
    ),
)
def rule_cve20250128(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-0128 in PAN-OS configurations.
    A denial-of-service (DoS) vulnerability in the Simple Certificate Enrollment Protocol (SCEP) 
    authentication feature enables an unauthenticated attacker to initiate system reboots using 
    a maliciously crafted packet. Repeated attempts cause the firewall to enter maintenance mode.
    
    NOTE: You do not need to have explicitly configured SCEP on your firewall to be at risk.
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
        """Check if device version is vulnerable"""
        device_norm = normalize_version(device_version)
        
        # Define vulnerable version ranges
        vulnerable_ranges = [
            # PAN-OS 11.2: < 11.2.3
            ((11, 2, 0, 0), (11, 2, 3, 0)),
            # PAN-OS 11.1: < 11.1.5
            ((11, 1, 0, 0), (11, 1, 5, 0)),
            # PAN-OS 11.0: < 11.0.6
            ((11, 0, 0, 0), (11, 0, 6, 0)),
            # PAN-OS 10.2: < 10.2.10-h17
            ((10, 2, 0, 0), (10, 2, 10, 17)),
            # PAN-OS 10.1: < 10.1.14-h11
            ((10, 1, 0, 0), (10, 1, 14, 11)),
        ]
        
        for min_version, max_version in vulnerable_ranges:
            if min_version <= device_norm < max_version:
                return True
        
        # All versions older than 10.1 are presumed affected (EoL)
        if device_norm < (10, 1, 0, 0):
            return True
                
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

    # Check if SCEP mitigation is applied
    scep_status = commands.show_scep_status
    mitigation_applied = 'yes' in scep_status.lower() if scep_status else False
    
    # If mitigation is applied, device is protected
    if mitigation_applied:
        return

    # Check if this is Cloud NGFW (not affected)
    model_match = re.search(r'model:\s*(\S+)', version_output)
    if model_match and 'cloud' in model_match.group(1).lower():
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0128. "
        f"Running vulnerable PAN-OS version {version}. "
        "A DoS vulnerability in SCEP authentication allows unauthenticated attackers to initiate "
        "system reboots using maliciously crafted packets. Repeated attempts cause maintenance mode. "
        "NOTE: You do not need to have explicitly configured SCEP to be at risk. "
        "MITIGATION: Run 'debug sslmgr set disable-scep-auth-cookie yes' (reapply after reboot) "
        "or upgrade to a fixed version: 11.2.3+, 11.1.5+, 11.0.6+, 10.2.10-h17+, or 10.1.14-h11+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2025-0128"
    )