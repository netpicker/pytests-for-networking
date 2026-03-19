from comfy import high

@high(
    name='rule_cve202521597',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration protocols bgp | display set',
        show_config_routing_options='show configuration routing-options | display set'
    ),
)
def rule_cve202521597(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-21597 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, logically adjacent BGP peer to cause
    Denial of Service (DoS) when BGP rib-sharding and update-threading are configured
    and a BGP peer flap is done with specific timing.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = [
        # All versions before 20.4R3-S8
        '20.4R1', '20.4R2', '20.4R3', '20.4R3-S1', '20.4R3-S2', '20.4R3-S3', '20.4R3-S4', '20.4R3-S5', '20.4R3-S6', '20.4R3-S7',
        # 21.2 versions before 21.2R3-S6
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5',
        # 21.3 versions before 21.3R3-S5
        '21.3R1', '21.3R2', '21.3R3', '21.3R3-S1', '21.3R3-S2', '21.3R3-S3', '21.3R3-S4',
        # 21.4 versions before 21.4R3-S4
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        # 22.1 versions before 22.1R3-S3
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2',
        # 22.2 versions before 22.2R3-S1
        '22.2R1', '22.2R2', '22.2R3',
        # 22.3 versions before 22.3R3
        '22.3R1', '22.3R2',
        # 22.4 versions before 22.4R3
        '22.4R1', '22.4R2'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for vulnerable BGP configuration
    bgp_config = commands.show_config_bgp
    routing_options_config = commands.show_config_routing_options

    # Check if BGP is configured
    has_bgp = 'protocols bgp' in bgp_config and bgp_config.strip() != ''

    if not has_bgp:
        return

    # Check for rib-sharding configuration
    has_rib_sharding = 'rib-sharding' in routing_options_config

    # Check for update-threading configuration
    has_update_threading = 'update-threading' in routing_options_config

    # Device is vulnerable if both rib-sharding and update-threading are configured
    is_vulnerable = has_rib_sharding and has_update_threading

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-21597. "
        "The device is running a vulnerable version of Junos OS with BGP rib-sharding and update-threading configured, "
        "which makes it susceptible to rpd crashes and Denial of Service (DoS) when BGP peer flapping occurs. "
        "For more information, see https://supportportal.juniper.net/JSA88139"
    )