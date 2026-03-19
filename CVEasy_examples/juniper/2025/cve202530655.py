import re
from comfy import high


@high(
    name='rule_cve202530655',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_bgp_config='show configuration protocols bgp | display set',
        show_routing_options='show configuration routing-options | display set'
    ),
)
def rule_cve202530655(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30655 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows a local, low-privileged attacker to cause a DoS condition
    by executing a specific "show bgp neighbor" CLI command when BGP RIB sharding and
    update-threading is enabled, causing rpd to crash.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # From 21.4 before 21.4R3-S8
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7',
        # From 22.2 before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # From 22.4 before 22.4R3-S2
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1',
        # From 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # From 23.4 before 23.4R2
        '23.4R1'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if BGP is configured
    bgp_config = commands.show_bgp_config
    has_bgp = 'set protocols bgp' in bgp_config

    if not has_bgp:
        return

    # Check if BGP RIB sharding is enabled
    routing_options = commands.show_routing_options
    has_rib_sharding = 'set routing-options rib-sharding' in routing_options

    # Check if update-threading is enabled
    has_update_threading = 'set routing-options bgp update-threading' in routing_options

    # Device is vulnerable if both RIB sharding and update-threading are enabled
    is_vulnerable = has_rib_sharding and has_update_threading

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-30655. "
        "The device is running a vulnerable version of Junos OS with BGP RIB sharding and update-threading enabled, "
        "which makes it susceptible to rpd crashes through 'show bgp neighbor' command execution. "
        "For more information, see https://supportportal.juniper.net/JSA88325"
    )