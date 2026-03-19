import re
from comfy import high

@high(
    name='rule_cve202552984',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_static_routes='show configuration routing-options static | display set',
        show_rpd_crashes='show system core-dumps | match rpd'
    ),
)
def rule_cve202552984(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52984 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    condition by sending a gNMI query for a static route that points to a reject next hop,
    which crashes the routing protocol daemon (rpd).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # 21.4 versions before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # 22.2 versions before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # 22.4 versions before 22.4R3-S6
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5',
        # 23.2 versions before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # 23.4 versions before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # 24.2 versions before 24.2R1-S2, 24.2R2
        '24.2R1', '24.2R1-S1'
    ]

    # Extract exact version token and check if it is vulnerable
    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ""
    version_vulnerable = version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for static routes with reject next hop
    static_routes_output = commands.show_config_static_routes
    has_reject_static_route = 'reject' in static_routes_output

    # If no reject static routes configured, device is not vulnerable
    if not has_reject_static_route:
        return

    # Check for gNMI configuration (implicit vulnerability if reject routes exist)
    # The vulnerability is triggered when gNMI queries are processed for static routes with reject next hop
    
    # Check for rpd crashes
    rpd_crashes_output = commands.show_rpd_crashes
    has_rpd_crashes = 'rpd' in rpd_crashes_output and rpd_crashes_output.strip()

    # Assert that the device is not vulnerable
    assert not has_reject_static_route, (
        f"Device {device.name} is vulnerable to CVE-2025-52984. "
        "The device is running a vulnerable version of Junos OS with static routes configured "
        "with reject next hop, which makes it susceptible to rpd crashes when gNMI queries are processed. "
        "For more information, see https://supportportal.juniper.net/JSA88984"
    )