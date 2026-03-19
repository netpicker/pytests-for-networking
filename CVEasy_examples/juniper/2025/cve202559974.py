from comfy import high


@high(
    name='rule_cve202559974',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_space_version=(
            'show configuration | display set | match "junos-space"'
        ),
        show_security_director=(
            'show configuration | display set | match "security-director"'
        ),
    ),
)
def rule_cve202559974(configuration, commands, device, devices):
    """
    CVE-2025-59974: XSS in Juniper Security Director allows stored script
    injection. Affects all versions before 24.1R4.
    """
    version_output = commands.show_version
    space_config = commands.show_space_version
    security_director_config = commands.show_security_director

    is_security_director = (
        (
            'set' in security_director_config
            and 'security-director' in security_director_config
        )
        or (
            'set' in space_config
            and 'junos-space' in space_config
        )
    )
    if not is_security_director:
        return

    vulnerable_version_patterns = [
        '19.', '20.', '21.', '22.', '23.',
        '24.1R1', '24.1R2', '24.1R3',
    ]
    version_vulnerable = any(
        pattern in version_output
        for pattern in vulnerable_version_patterns
    )

    safe_versions = ['24.1R4', '24.2', '24.3', '24.4', '25.']
    version_safe = any(
        safe_ver in version_output for safe_ver in safe_versions
    )
    if version_safe:
        return

    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-59974. "
        "Running a vulnerable Junos Space Security Director version "
        "(before 24.1R4) allows XSS attacks. "
        "Upgrade to Security Director 24.1R4 or later. "
        "See https://supportportal.juniper.net/CVE-2025-59974"
    )
