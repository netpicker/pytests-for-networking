import re
from comfy import high

@high(
    name='rule_cve202521600',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp=(
            'show configuration protocols bgp | display set'
        ),
        show_config_traceoptions=(
            'show configuration protocols bgp traceoptions | display set'
        ),
        show_config_bgp_ls=(
            'show configuration protocols bgp | display set'
            ' | match traffic-engineering'
        )
    ),
)
def rule_cve202521600(configuration, commands, device, devices):
    """
    CVE-2025-21600: An unauthenticated logically adjacent BGP peer can crash
    rpd by sending a malformed BGP packet. Only affects systems with BGP
    traceoptions enabled or BGP family traffic-engineering configured.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4',
        '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        '22.3R1', '22.3R2', '22.3R3',
        '22.3R3-S1', '22.3R3-S2', '22.3R3-S3',
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2',
        '24.2R1', '24.2R1-S1',
    ]

    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    if extracted_version not in vulnerable_versions:
        return

    # Check if BGP is configured
    bgp_config = commands.show_config_bgp
    if 'protocols bgp' not in bgp_config or not bgp_config.strip():
        return

    # Check for vulnerable configurations (filter comment lines)
    traceoptions_output = commands.show_config_traceoptions
    traceoptions_lines = [
        line for line in traceoptions_output.splitlines()
        if not line.strip().startswith('#')
    ]
    has_traceoptions = any('traceoptions' in line for line in traceoptions_lines)

    bgp_ls_output = commands.show_config_bgp_ls
    bgp_ls_lines = [
        line for line in bgp_ls_output.splitlines()
        if not line.strip().startswith('#')
    ]
    has_bgp_ls = any('traffic-engineering' in line for line in bgp_ls_lines)

    assert not (has_traceoptions or has_bgp_ls), (
        f"Device {device.name} is vulnerable to CVE-2025-21600. "
        "The device runs a vulnerable Junos OS with BGP configured and either "
        "BGP traceoptions enabled or BGP family traffic-engineering (BGP-LS) "
        "configured. An unauthenticated adjacent BGP peer can send a malformed "
        "packet to crash rpd, causing a sustained DoS condition. "
        "See https://supportportal.juniper.net/JSA88316"
    )
