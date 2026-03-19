from comfy import high


@high(
    name='rule_cve202559994',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space=(
            'show configuration | display set | match "junos-space"'
        ),
    ),
)
def rule_cve202559994(configuration, commands, device, devices):
    """
    CVE-2025-59994: XSS in Junos Space Quick Template page. Affects all
    versions before 24.1R4.
    """
    version_output = commands.show_version
    config_output = commands.show_config_junos_space

    is_junos_space = (
        'set system services junos-space' in config_output
        or 'Junos Space' in version_output
    )
    if not is_junos_space:
        return

    is_fixed_version = False
    if any(v in version_output for v in [
        '24.1R4', '24.2', '24.3', '24.4', '25.', '26.', '27.',
    ]):
        is_fixed_version = True

    if is_fixed_version:
        return

    version_patterns = [
        '23.', '22.', '21.', '20.', '19.',
        '24.1R1', '24.1R2', '24.1R3',
    ]
    is_vulnerable_version = any(
        pattern in version_output for pattern in version_patterns
    )

    assert not is_vulnerable_version, (
        f"Device {device.name} is vulnerable to CVE-2025-59994. "
        "Running a vulnerable Junos Space version (before 24.1R4) allows "
        "XSS attacks in the Quick Template page. "
        "Upgrade to 24.1R4 or later. "
        "See https://supportportal.juniper.net/CVE-2025-59994"
    )
