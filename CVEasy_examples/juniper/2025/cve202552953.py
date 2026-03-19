import re
from comfy import high


@high(
    name='rule_cve202552953',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_bgp_summary='show bgp summary',
        show_bgp_config='show configuration protocols bgp | display set'
    ),
)
def rule_cve202552953(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52953 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated adjacent attacker sending a valid BGP UPDATE
    packet to cause a BGP session reset, resulting in a Denial of Service (DoS).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # from 21.4 before 21.4R3-S11
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9', '21.4R3-S10',
        # from 22.2 before 22.2R3-S7
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5', '22.2R3-S6',
        # from 22.4 before 22.4R3-S7
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5', '22.4R3-S6',
        # from 23.2 before 23.2R2-S4
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2', '23.2R2-S3',
        # from 23.4 before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # from 24.2 before 24.2R2
        '24.2R1', '24.2R1-S1',
        # from 24.4 before 24.4R1-S3, 24.4R2
        '24.4R1', '24.4R1-S1', '24.4R1-S2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if BGP is configured
    bgp_config_output = commands.show_bgp_config
    bgp_summary_output = commands.show_bgp_summary

    # Check if BGP is enabled (either iBGP or eBGP)
    has_bgp_config = 'set protocols bgp' in bgp_config_output
    has_bgp_sessions = 'Peer' in bgp_summary_output or 'Established' in bgp_summary_output

    is_bgp_enabled = has_bgp_config or has_bgp_sessions

    # Assert that the device is not vulnerable
    assert not is_bgp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-52953. "
        "The device is running a vulnerable version of Junos OS with BGP enabled, "
        "which makes it susceptible to BGP session resets through malicious BGP UPDATE packets. "
        "This affects both iBGP and eBGP, and both IPv4 and IPv6. "
        "For more information, see https://supportportal.juniper.net/JSA88953"
    )