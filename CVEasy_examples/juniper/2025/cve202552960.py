import re
from comfy import high


@high(
    name='rule_cve202552960',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_security_alg='show configuration | display set | match "security alg sip"'
    ),
)
def rule_cve202552960(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52960 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by sending specific SIP packets when memory utilization is high, causing flowd/mspmand crashes.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = []
    
    # All versions before 22.4R3-S7
    vulnerable_versions.extend([
        '21.2R', '21.3R', '21.4R',
        '22.1R', '22.2R', '22.3R',
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5', '22.4R3-S6'
    ])
    
    # From 23.2 before 23.2R2-S4
    vulnerable_versions.extend([
        '23.2R1', '23.2R2',
        '23.2R2-S1', '23.2R2-S2', '23.2R2-S3'
    ])
    
    # From 23.4 before 23.4R2-S5
    vulnerable_versions.extend([
        '23.4R1', '23.4R2',
        '23.4R2-S1', '23.4R2-S2', '23.4R2-S3', '23.4R2-S4'
    ])
    
    # From 24.2 before 24.2R2
    vulnerable_versions.extend([
        '24.2R1'
    ])

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is MX Series or SRX Series
    chassis_output = commands.show_chassis_hardware
    is_vulnerable_platform = 'MX' in chassis_output or 'SRX' in chassis_output

    if not is_vulnerable_platform:
        return

    # Check if SIP ALG is enabled
    alg_output = commands.show_security_alg
    sip_alg_enabled = 'security alg sip' in alg_output and 'disable' not in alg_output

    # Assert that the device is not vulnerable
    assert not sip_alg_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-52960. "
        "The device is running a vulnerable version of Junos OS on MX/SRX Series hardware with SIP ALG enabled, "
        "which makes it susceptible to DoS attacks through specially crafted SIP packets during high memory utilization. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )