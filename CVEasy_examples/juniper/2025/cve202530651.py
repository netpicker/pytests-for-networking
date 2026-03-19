import re
from comfy import high

@high(
    name='rule_cve202530651',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_ipv6='show configuration | display set | match "protocols router-advertisement"',
        show_ipv6_interfaces='show configuration | display set | match "family inet6"'
    ),
)
def rule_cve202530651(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30651 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by sending a specific ICMPv6 packet to an interface with "protocols router-advertisement"
    configured, causing rpd to crash and restart.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        '20.4R1', '20.4R2', '20.4R3',
        # from 21.4 before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # from 22.2 before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # from 22.4 before 22.4R3-S4
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3',
        # from 23.2 before 23.2R2-S2
        '23.2R1', '23.2R2', '23.2R2-S1',
        # from 23.4 before 23.4R2
        '23.4R1'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if IPv6 is configured
    ipv6_config = commands.show_ipv6_interfaces
    has_ipv6 = 'family inet6' in ipv6_config

    # If IPv6 is not configured, device is not vulnerable
    if not has_ipv6:
        return

    # Check if router-advertisement is configured
    router_adv_config = commands.show_config_ipv6
    has_router_advertisement = 'protocols router-advertisement' in router_adv_config

    # Assert that the device is not vulnerable
    assert not has_router_advertisement, (
        f"Device {device.name} is vulnerable to CVE-2025-30651. "
        "The device is running a vulnerable version of Junos OS with IPv6 and "
        "protocols router-advertisement configured, which makes it susceptible to DoS "
        "attacks via malicious ICMPv6 packets causing rpd crashes. "
        "For more information, see https://supportportal.juniper.net/JSA88888"
    )