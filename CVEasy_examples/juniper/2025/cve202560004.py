import re

from comfy import high


@high(
    name='rule_cve202560004',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_bgp_config='show configuration protocols bgp | display set',
        show_bgp_summary='show bgp summary',
    ),
)
def rule_cve202560004(configuration, commands, device, devices):
    """
    CVE-2025-60004: DoS via malicious BGP EVPN update message causing rpd
    crash and restart over established BGP session.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        '23.4R2-S3', '23.4R2-S4',
        '24.2R2',
        '24.4R1', '24.4R1-S1', '24.4R1-S2',
        '23.4R2-S2-EVO', '23.4R2-S3-EVO', '23.4R2-S4-EVO',
        '24.2R2-EVO',
        '24.4R1-EVO', '24.4R1-S1-EVO', '24.4R1-S2-EVO',
    ]

    match = re.search(r'Junos(?:\s+OS\s+Evolved)?:\s+(\S+)', version_output)
    version = match.group(1) if match else ''
    if version not in vulnerable_versions:
        return

    bgp_config_output = commands.show_bgp_config
    has_bgp_config = 'set protocols bgp' in bgp_config_output
    if not has_bgp_config:
        return

    bgp_summary_output = commands.show_bgp_summary
    has_established_bgp = (
        'Established' in bgp_summary_output
        or 'Active' in bgp_summary_output
    )

    assert not has_established_bgp, (
        f"Device {device.name} is vulnerable to CVE-2025-60004. "
        "Running a vulnerable Junos OS version with BGP configured and "
        "active sessions allows rpd crashes via malicious BGP EVPN update "
        "messages. "
        "See https://supportportal.juniper.net/JSA88588"
    )
