import re

from comfy import high


@high(
    name='rule_cve202559962',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp=(
            'show configuration protocols bgp | display set'
        ),
        show_config_routing_options=(
            'show configuration routing-options | display set'
        ),
    ),
)
def rule_cve202559962(configuration, commands, device, devices):
    """
    CVE-2025-59962: rpd crash via indirect next-hop updates when BGP
    sharding is configured, causing DoS.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        '21.3R1', '21.3R2', '21.3R3',
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5',
        '22.1R1', '22.1R2', '22.1R3',
        '22.1R3-S1', '22.1R3-S2', '22.1R3-S3', '22.1R3-S4', '22.1R3-S5',
        '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2',
        '22.3R1', '22.3R2', '22.3R3',
        '22.3R3-S1', '22.3R3-S2',
        '22.4R1', '22.4R2',
        '23.2R1',
    ]

    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ''
    if version not in vulnerable_versions:
        return

    bgp_config = commands.show_config_bgp
    routing_options_config = commands.show_config_routing_options

    has_bgp_sharding = (
        'bgp-sharding' in routing_options_config
        or 'bgp-sharding' in bgp_config
    )
    has_bgp_configured = (
        'protocols bgp' in bgp_config
        or len(bgp_config.strip()) > 0
    )

    assert not (has_bgp_sharding and has_bgp_configured), (
        f"Device {device.name} is vulnerable to CVE-2025-59962. "
        "Running a vulnerable Junos OS version with BGP sharding configured "
        "makes it susceptible to rpd crashes via indirect next-hop updates. "
        "See https://supportportal.juniper.net/JSA88588"
    )
