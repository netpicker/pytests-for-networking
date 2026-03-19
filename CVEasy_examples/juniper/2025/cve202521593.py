import re
from comfy import high

@high(
    name='rule_cve202521593',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_srv6='show configuration protocols source-packet-routing | display set | match srv6',
        show_config_bgp='show configuration protocols bgp | display set'
    ),
)
def rule_cve202521593(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-21593 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated network-based attacker to cause a DoS
    by sending malformed BGP UPDATE packets to devices with SRv6 enabled, causing rpd to crash.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # 21.4 before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # 22.2 before 22.2R3-S5
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        # 22.3 before 22.3R3-S4
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1', '22.3R3-S2', '22.3R3-S3',
        # 22.4 before 22.4R3-S3
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2',
        # 23.2 before 23.2R2-S2
        '23.2R1', '23.2R2', '23.2R2-S1',
        # 23.4 before 23.4R2
        '23.4R1'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if SRv6 is enabled
    srv6_output = commands.show_config_srv6
    srv6_enabled = 'srv6' in srv6_output.lower() and len(srv6_output.strip()) > 0

    # If SRv6 is not enabled, device is not vulnerable
    if not srv6_enabled:
        return

    # Check if BGP is configured
    bgp_output = commands.show_config_bgp
    bgp_configured = 'bgp' in bgp_output.lower() and len(bgp_output.strip()) > 0

    # If BGP is not configured, device is not vulnerable
    if not bgp_configured:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-21593. "
        "The device is running a vulnerable version of Junos OS with SRv6 and BGP enabled, "
        "which makes it susceptible to DoS attacks through malformed BGP UPDATE packets that crash rpd. "
        "For more information, see https://supportportal.juniper.net/JSA88316"
    )