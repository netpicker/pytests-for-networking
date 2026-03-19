import re
from comfy import high

@high(
    name='rule_cve202552980',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_bgp_summary='show bgp summary',
        show_bgp_config='show configuration protocols bgp | display set'
    ),
)
def rule_cve202552980(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52980 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by sending a BGP update with a specific optional transitive path attribute that crashes rpd.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '22.1R1', '22.1R2', '22.1R3', '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1', '22.3R3-S2',
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1',
        '23.2R1', '23.2R1-S1', '23.2R1-S2',
        '23.4R1', '23.4R1-S1', '23.4R1-S2'
    ]

    # Extract exact version token and check if it is vulnerable
    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ""
    version_vulnerable = version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is SRX300 Series
    chassis_output = commands.show_chassis_hardware
    is_srx300_platform = 'SRX300' in chassis_output

    if not is_srx300_platform:
        return

    # Check if BGP is configured and active
    bgp_summary = commands.show_bgp_summary
    bgp_config = commands.show_bgp_config
    
    has_bgp_configured = 'set protocols bgp' in bgp_config
    has_active_bgp_sessions = 'Established' in bgp_summary or 'Active' in bgp_summary or 'Connect' in bgp_summary

    # Device is vulnerable if BGP is configured
    is_vulnerable = has_bgp_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-52980. "
        "The device is running a vulnerable version of Junos OS on SRX300 Series hardware with BGP configured, "
        "which makes it susceptible to rpd crashes when receiving BGP updates with specific optional transitive path attributes. "
        "This affects both eBGP and iBGP over IPv4 and IPv6. "
        "For more information, see https://supportportal.juniper.net/JSA88980"
    )