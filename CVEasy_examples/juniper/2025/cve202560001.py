from comfy import high


@high(
    name='rule_cve202560001',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space=(
            'show configuration | display set | match "junos-space"'
        ),
    ),
)
def rule_cve202560001(configuration, commands, device, devices):
    """
    CVE-2025-60001: XSS in Junos Space Generate Report page allows script
    injection with target user permissions. Affects all versions before
    24.1R4.
    """
    version_output = commands.show_version

    vulnerable_version_prefixes = [
        '19.', '20.', '21.', '22.', '23.',
        '24.1R1', '24.1R2', '24.1R3',
    ]

    version_vulnerable = any(
        version in version_output
        for version in vulnerable_version_prefixes
    )
    if not version_vulnerable:
        return

    config_output = commands.show_config_junos_space
    has_junos_space = (
        'set system services junos-space' in config_output
    )
    if not has_junos_space:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-60001. "
        "Running a vulnerable Junos Space version (before 24.1R4) with "
        "Junos Space configured allows XSS in the Generate Report page. "
        "Upgrade to 24.1R4 or later. "
        "See https://supportportal.juniper.net/CVE-2025-60001"
    )
