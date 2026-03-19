import re

from comfy import high


@high(
    name='rule_cve202559975',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_httpd=(
            'show configuration | display set | match '
            '"system services web-management"'
        ),
    ),
)
def rule_cve202559975(configuration, commands, device, devices):
    """
    CVE-2025-59975: DoS via API flooding in Junos Space before
    22.2R1 Patch V3 and 23.1 before 23.1R1 Patch V3.
    """
    version_output = commands.show_version

    match = re.search(r'(\d+\.\d+R\d+(?:-\S+)?)', version_output)
    version = match.group(1) if match else ''

    vulnerable_versions_22_2 = [
        '22.1', '22.2R1', '22.2R1-S1', '22.2R1-S2',
        '22.2R1-PV1', '22.2R1-PV2',
    ]

    vulnerable_versions_23_1 = [
        '23.1R1', '23.1R1-S1', '23.1R1-S2',
        '23.1R1-PV1', '23.1R1-PV2',
    ]

    version_vulnerable = (
        version in vulnerable_versions_22_2
        or version in vulnerable_versions_23_1
    )

    if not version_vulnerable and 'Junos Space' in version_output:
        for line in version_output.splitlines():
            if 'version' in line.lower() or 'junos' in line.lower():
                if '21.' in line or '20.' in line or '19.' in line:
                    version_vulnerable = True

    if not version_vulnerable:
        return

    config_output = commands.show_config_httpd
    httpd_enabled = 'system services web-management' in config_output

    assert not httpd_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-59975. "
        "Running a vulnerable Junos Space version with web-management "
        "enabled allows resource exhaustion DoS via API flooding. "
        "Upgrade to 22.2R1 Patch V3 or 23.1R1 Patch V3 or later. "
        "See https://supportportal.juniper.net/JSA88888"
    )
