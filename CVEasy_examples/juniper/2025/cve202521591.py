import re
from comfy import high

@high(
    name='rule_cve202521591',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_dhcp_snooping='show configuration | display set | match "dhcp-security"',
        show_chassis_hardware='show chassis hardware'
    ),
)
def rule_cve202521591(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-21591 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, adjacent attacker to send a DHCP packet
    with a malformed DHCP option to cause jdhcpd to crash when DHCP snooping is enabled,
    creating a Denial of Service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = []
    
    # 23.1 before 23.2R2-S3
    vulnerable_versions.extend([
        '23.1R1', '23.1R2', '23.1R3',
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2'
    ])
    
    # 23.4 before 23.4R2-S3
    vulnerable_versions.extend([
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2'
    ])
    
    # 24.2 before 24.2R2
    vulnerable_versions.extend([
        '24.2R1', '24.2R1-S1', '24.2R1-S2'
    ])

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is vSRX Series (not vulnerable)
    chassis_output = commands.show_chassis_hardware
    is_vsrx_platform = 'vSRX' in chassis_output or 'VSRX' in chassis_output

    if is_vsrx_platform:
        return

    # Check if DHCP snooping is enabled
    dhcp_snooping_output = commands.show_config_dhcp_snooping
    dhcp_snooping_enabled = 'dhcp-security' in dhcp_snooping_output and dhcp_snooping_output.strip() != ''

    # If DHCP snooping is not enabled, device is not vulnerable
    if not dhcp_snooping_enabled:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-21591. "
        "The device is running a vulnerable version of Junos OS with DHCP snooping enabled, "
        "which makes it susceptible to jdhcpd crashes through malformed DHCP packets causing a Denial of Service (DoS) condition. "
        "For more information, see https://supportportal.juniper.net/JSA88139"
    )