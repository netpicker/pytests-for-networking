import re
from comfy import high

@high(
    name='rule_cve202521602',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_bgp_summary='show bgp summary',
        show_bgp_config='show configuration protocols bgp | display set',
        show_rpd_crashes='show system core-dumps | match rpd'
    ),
)
def rule_cve202521602(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-21602 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated adjacent attacker sending a specific BGP 
    update packet to cause rpd to crash and restart, resulting in a Denial of Service (DoS).
    This affects both iBGP and eBGP, and both IPv4 and IPv6.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1', '22.3R3-S2', '22.3R3-S3',
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2',
        '24.2R1', '24.2R1-S1', '24.2R2'
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
    
    # Check if BGP is enabled and has neighbors
    has_bgp_config = 'set protocols bgp' in bgp_config_output
    has_bgp_neighbors = 'Peer' in bgp_summary_output or 'peer' in bgp_summary_output.lower()

    # If BGP is not configured or has no neighbors, device is not vulnerable
    if not has_bgp_config or not has_bgp_neighbors:
        return

    # Check for recent rpd crashes (indicator of exploitation)
    rpd_crashes_output = commands.show_rpd_crashes
    has_rpd_crashes = 'rpd' in rpd_crashes_output and rpd_crashes_output.strip() != ''

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-21602. "
        "The device is running a vulnerable version of Junos OS with BGP enabled, "
        "which makes it susceptible to rpd crashes through malicious BGP update packets. "
        "An unauthenticated adjacent attacker can cause a Denial of Service (DoS) condition. "
        f"{'Recent rpd crashes detected - possible exploitation. ' if has_rpd_crashes else ''}"
        "For more information, see https://supportportal.juniper.net/JSA88316"
    )