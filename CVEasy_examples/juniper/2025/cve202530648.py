import re
from comfy import high

@high(
    name='rule_cve202530648',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_dhcp_security='show configuration | display set | match "dhcp-security"',
        show_jdhcpd_crashes='show system core-dumps | match jdhcpd'
    ),
)
def rule_cve202530648(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30648 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, adjacent attacker to cause the jdhcpd
    process to crash resulting in a Denial of Service (DoS) when dhcp-security is enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # from 21.4 before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # from 22.2 before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # from 22.4 before 22.4R3-S6
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5',
        # from 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # from 23.4 before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # from 24.2 before 24.2R2
        '24.2R1', '24.2R1-S1'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if dhcp-security is enabled
    dhcp_security_output = commands.show_config_dhcp_security
    dhcp_security_enabled = 'dhcp-security' in dhcp_security_output and dhcp_security_output.strip() != ''

    # If dhcp-security is not enabled, device is not vulnerable
    if not dhcp_security_enabled:
        return

    # Check for jdhcpd crashes
    jdhcpd_crashes = commands.show_jdhcpd_crashes
    has_jdhcpd_crashes = 'jdhcpd' in jdhcpd_crashes and jdhcpd_crashes.strip() != ''

    # Assert that the device is not vulnerable
    assert not dhcp_security_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-30648. "
        "The device is running a vulnerable version of Junos OS with dhcp-security enabled, "
        "which makes it susceptible to jdhcpd process crashes through malformed DHCP packets. "
        "For more information, see https://supportportal.juniper.net/JSA88648"
    )