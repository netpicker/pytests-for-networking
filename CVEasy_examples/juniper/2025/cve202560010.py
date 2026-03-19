import re

from comfy import high


@high(
    name='rule_cve202560010',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_radius=(
            'show configuration | display set | match "system radius-server"'
        ),
        show_config_authentication=(
            'show configuration | display set | match '
            '"system authentication-order"'
        ),
    ),
)
def rule_cve202560010(configuration, commands, device, devices):
    """
    CVE-2025-60010: RADIUS password-expiry bypass allows access without
    enforcing required password change.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3',
        '22.4R3-S4', '22.4R3-S5', '22.4R3-S6', '22.4R3-S7',
        '23.2R1', '23.2R1-S1', '23.2R1-S2',
        '23.2R2', '23.2R2-S1', '23.2R2-S2', '23.2R2-S3',
        '23.4R1', '23.4R1-S1', '23.4R1-S2',
        '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3', '23.4R2-S4',
        '24.2R1', '24.2R1-S1', '24.2R1-S2', '24.2R2',
        '24.4R1', '24.4R1-S1', '24.4R1-S2',
    ]

    older_prefixes = [
        '21.1', '21.2', '21.3', '21.4', '22.1', '22.2', '22.3',
    ]

    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ''

    version_vulnerable = (
        version in vulnerable_versions
        or any(version.startswith(p) for p in older_prefixes)
    )
    if not version_vulnerable:
        return

    radius_config = commands.show_config_radius
    auth_order_config = commands.show_config_authentication

    has_radius_server = (
        'system radius-server' in radius_config
        and radius_config.strip()
    )
    uses_radius_auth = 'radius' in auth_order_config

    assert not (has_radius_server and uses_radius_auth), (
        f"Device {device.name} is vulnerable to CVE-2025-60010. "
        "Running a vulnerable Junos OS version with RADIUS authentication "
        "allows users with expired passwords to login without enforcing "
        "password change. "
        "See https://supportportal.juniper.net/JSA88144"
    )
