from comfy import high


@high(
    name='rule_cve202559993',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_space_version='show version | match "Junos Space"',
        show_space_config=(
            'show configuration | display set | match "junos-space"'
        ),
    ),
)
def rule_cve202559993(configuration, commands, device, devices):
    """
    CVE-2025-59993: XSS in Junos Space Node Setting fields allows script
    injection with target user (including admin) permissions. Affects all
    versions before 24.1R4.
    """
    version_output = commands.show_version
    space_version_output = commands.show_space_version

    is_space_device = (
        'Junos Space' in space_version_output
        or 'Space' in version_output
    )
    if not is_space_device:
        return

    vulnerable_major_versions = [
        '19.', '20.', '21.', '22.', '23.',
        '24.1R1', '24.1R2', '24.1R3',
    ]

    version_vulnerable = any(
        version in space_version_output or version in version_output
        for version in vulnerable_major_versions
    )

    if not version_vulnerable:
        return

    space_config_output = commands.show_space_config
    space_configured = (
        bool(space_config_output.strip())
        and 'set system services junos-space' in space_config_output
    )
    if not space_configured:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-59993. "
        "Running a vulnerable Junos Space version (before 24.1R4) with "
        "Junos Space configured allows XSS via Node Setting fields. "
        "Upgrade to 24.1R4 or later. "
        "See https://supportportal.juniper.net/JSA88888"
    )
