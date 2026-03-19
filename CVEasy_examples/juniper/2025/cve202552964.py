import re
from comfy import high

@high(
    name='rule_cve202552964',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration protocols bgp | display set'
    ),
)
def rule_cve202552964(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52964 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by sending specific BGP UPDATE packets that crash the Routing Protocol Daemon (rpd)
    when BGP multipath with pause-computation-during-churn is configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.4R3-S7
        '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6',
        '21.4R2', '21.4R1',
        '21.3', '21.2', '21.1', '20.4', '20.3', '20.2', '20.1',
        # From 22.3 before 22.3R3-S3
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1', '22.3R3-S2',
        # From 22.4 before 22.4R3-S5
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        # From 23.2 before 23.2R2
        '23.2R1', '23.2R1-S1', '23.2R1-S2',
        # From 23.4 before 23.4R2
        '23.4R1', '23.4R1-S1', '23.4R1-S2'
    ]

    # Extract exact version token and check if it is vulnerable
    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ""
    version_vulnerable = version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for vulnerable configuration: BGP multipath with pause-computation-during-churn
    bgp_config = commands.show_config_bgp
    
    has_bgp_multipath = 'multipath' in bgp_config
    has_pause_computation = 'pause-computation-during-churn' in bgp_config

    # Device is vulnerable if both conditions are met
    is_vulnerable = has_bgp_multipath and has_pause_computation

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-52964. "
        "The device is running a vulnerable version of Junos OS with BGP multipath "
        "and pause-computation-during-churn configured, which makes it susceptible to "
        "rpd crashes when receiving specific BGP UPDATE packets from established BGP peers. "
        "For more information, see https://supportportal.juniper.net/JSA88964"
    )