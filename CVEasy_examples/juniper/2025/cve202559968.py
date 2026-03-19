from comfy import high


@high(
    name='rule_cve202559968',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_space_version='show version | match "Junos Space"',
        show_security_director=(
            'show configuration | display set | match "security-director"'
        ),
    ),
)
def rule_cve202559968(configuration, commands, device, devices):
    """
    CVE-2025-59968: Unauthenticated attacker can read or modify metadata
    via Junos Space Security Director web interface, causing managed SRX
    devices to permit traffic that should be blocked. Affects versions
    before 24.1R3 Patch V4.
    """
    version_output = commands.show_version
    space_version_output = commands.show_space_version

    is_space_security_director = (
        'Junos Space' in space_version_output
        and not space_version_output.strip().startswith('#')
    )
    if not is_space_security_director:
        return

    if '24.1R3' in version_output and 'Patch V4' in version_output:
        return

    if '24.1R3' in version_output and any(
        f'Patch V{i}' in version_output for i in range(5, 20)
    ):
        return

    if any(v in version_output for v in ['24.2', '24.3', '24.4', '25.']):
        return

    vulnerable_version_patterns = [
        '19.', '20.', '21.', '22.', '23.',
        '24.1R1', '24.1R2', '24.1R3',
    ]
    version_vulnerable = any(
        pattern in version_output
        for pattern in vulnerable_version_patterns
    )
    if not version_vulnerable:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-59968. "
        "Running a vulnerable Junos Space Security Director version "
        "(before 24.1R3 Patch V4) allows unauthenticated metadata "
        "read/modify attacks. "
        "Upgrade to 24.1R3 Patch V4 or later. "
        "See https://supportportal.juniper.net/JSA88888"
    )
