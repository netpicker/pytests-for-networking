import re

from comfy import high


@high(
    name='rule_cve202559999',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space=(
            'show configuration | display set | match "junos-space"'
        ),
    ),
)
def rule_cve202559999(configuration, commands, device, devices):
    """
    CVE-2025-59999: XSS in Junos Space API Access Profiles page.
    Affects all versions before 24.1R4.
    """
    version_output = commands.show_version

    if 'Junos Space' not in version_output:
        return

    version_match = re.search(r'(\d+)\.(\d+)R(\d+)', version_output)

    if not version_match:
        version_vulnerable = True
    else:
        major = int(version_match.group(1))
        minor = int(version_match.group(2))
        release = int(version_match.group(3))

        if major < 24:
            version_vulnerable = True
        elif major == 24 and minor < 1:
            version_vulnerable = True
        elif major == 24 and minor == 1 and release < 4:
            version_vulnerable = True
        else:
            version_vulnerable = False

    if not version_vulnerable:
        return

    config_output = commands.show_config_junos_space
    junos_space_configured = (
        config_output.strip().startswith('set')
        and 'junos-space' in config_output
    )

    assert not junos_space_configured, (
        f"Device {device.name} is vulnerable to CVE-2025-59999. "
        "Running a vulnerable Junos Space version (before 24.1R4) with "
        "Junos Space configured allows XSS in the API Access Profiles "
        "page. Upgrade to 24.1R4 or later. "
        "See https://supportportal.juniper.net/CVE-2025-59999"
    )
