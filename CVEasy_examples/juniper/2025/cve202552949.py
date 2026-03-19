import re
from comfy import high


@high(
    name='rule_cve202552949',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_evpn='show configuration | display set | match "protocols evpn"',
        show_config_bgp='show configuration | display set | match "protocols bgp"',
        show_rpd_crashes='show system core-dumps | match rpd'
    ),
)
def rule_cve202552949(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52949 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows a logically adjacent BGP peer sending a specifically malformed
    BGP packet to cause rpd to crash and restart, resulting in a Denial of Service (DoS).
    Only systems configured for Ethernet Virtual Private Networking (EVPN) signaling are vulnerable.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.4R3-S11
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', 
        '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9', '21.4R3-S10',
        '21.3', '21.2', '21.1', '20.4', '20.3', '20.2', '20.1',
        # From 22.2 before 22.2R3-S7
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5', '22.2R3-S6',
        # From 22.4 before 22.4R3-S7
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5', '22.4R3-S6',
        # From 23.2 before 23.2R2-S4
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2', '23.2R2-S3',
        # From 23.4 before 23.4R2-S5
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3', '23.4R2-S4',
        # From 24.2 before 24.2R2-S1
        '24.2R1', '24.2R2',
        # From 24.4 before 24.4R1-S3, 24.4R2
        '24.4R1', '24.4R1-S1', '24.4R1-S2', '24.4R2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if EVPN is configured
    evpn_output = commands.show_config_evpn
    has_evpn = 'protocols evpn' in evpn_output and evpn_output.strip() != ''

    # Check if BGP is configured
    bgp_output = commands.show_config_bgp
    has_bgp = 'protocols bgp' in bgp_output and bgp_output.strip() != ''

    # Device is vulnerable only if both EVPN and BGP are configured
    is_vulnerable = version_vulnerable and has_evpn and has_bgp

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-52949. "
        "The device is running a vulnerable version of Junos OS with EVPN signaling configured, "
        "which makes it susceptible to rpd crashes through malformed BGP packets from logically adjacent BGP peers. "
        "This affects both iBGP and eBGP, and both IPv4 and IPv6. "
        "For more information, see https://supportportal.juniper.net/JSA88949"
    )