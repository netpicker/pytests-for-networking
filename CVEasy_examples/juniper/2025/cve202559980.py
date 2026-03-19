import re

from comfy import high


@high(
    name='rule_cve202559980',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_ftp=(
            'show configuration system services ftp | display set'
        ),
        show_config_users=(
            'show configuration system login user | display set'
        ),
    ),
)
def rule_cve202559980(configuration, commands, device, devices):
    """
    CVE-2025-59980: Unauthenticated FTP authentication bypass when FTP
    is enabled and a user named "ftp" or "anonymous" is configured.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3',
        '22.4R3-S4', '22.4R3-S5', '22.4R3-S6', '22.4R3-S7',
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        '23.4R1', '23.4R1-S1', '23.4R1-S2',
    ]

    older_prefixes = ['21.2R', '21.3R', '21.4R', '22.1R', '22.2R', '22.3R']

    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ''

    version_vulnerable = (
        version in vulnerable_versions
        or any(version.startswith(p) for p in older_prefixes)
    )

    if not version_vulnerable:
        return

    ftp_config = commands.show_config_ftp
    ftp_enabled = 'set system services ftp' in ftp_config
    if not ftp_enabled:
        return

    users_config = commands.show_config_users
    has_ftp_user = 'set system login user ftp' in users_config
    has_anonymous_user = 'set system login user anonymous' in users_config

    assert not (has_ftp_user or has_anonymous_user), (
        f"Device {device.name} is vulnerable to CVE-2025-59980. "
        "Running a vulnerable Junos OS version with FTP enabled and an "
        "'ftp' or 'anonymous' user allows unauthenticated authentication "
        "bypass. "
        "See https://supportportal.juniper.net/JSA88125"
    )
