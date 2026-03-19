from comfy import high


@high(
    name='rule_cve202559992',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space=(
            'show configuration | display set | match "junos-space"'
        ),
    ),
)
def rule_cve202559992(configuration, commands, device, devices):
    """
    CVE-2025-59992: XSS in Junos Space Secure Console page allows script
    injection with target user permissions. Affects all versions before
    24.1R4.
    """
    version_output = commands.show_version

    vulnerable_version_patterns = [
        '19.1', '19.2', '19.3', '19.4',
        '20.1', '20.2', '20.3', '20.4',
        '21.1', '21.2', '21.3', '21.4',
        '22.1', '22.2', '22.3', '22.4',
        '23.1', '23.2', '23.3', '23.4',
        '24.1R1', '24.1R2', '24.1R3',
    ]

    version_vulnerable = any(
        version in version_output
        for version in vulnerable_version_patterns
    )
    if not version_vulnerable:
        return

    config_output = commands.show_config_junos_space
    has_junos_space = 'set system services junos-space' in config_output
    if not has_junos_space:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-59992. "
        "Running a vulnerable Junos Space version (before 24.1R4) with "
        "Junos Space configured allows XSS attacks in the Secure Console "
        "page. Upgrade to 24.1R4 or later. "
        "See https://supportportal.juniper.net/CVE-2025-59992"
    )
