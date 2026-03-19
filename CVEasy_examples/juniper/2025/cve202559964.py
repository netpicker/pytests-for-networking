import re

from comfy import high


@high(
    name='rule_cve202559964',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_sampling=(
            'show configuration | display set | match '
            '"forwarding-options sampling"'
        ),
    ),
)
def rule_cve202559964(configuration, commands, device, devices):
    """
    CVE-2025-59964: DoS via traffic to RE when forwarding-options sampling
    is enabled on SRX4700 devices, causing FPC crash and restart.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        '24.4R1', '24.4R1-S1', '24.4R1-S2',
        '24.4R2',
    ]

    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ''
    if version not in vulnerable_versions:
        return

    chassis_output = commands.show_chassis_hardware
    if 'SRX4700' not in chassis_output:
        return

    sampling_output = commands.show_config_sampling
    has_sampling_enabled = (
        'forwarding-options sampling' in sampling_output
        and sampling_output.strip() != ''
    )

    assert not has_sampling_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-59964. "
        "Running a vulnerable Junos OS version on SRX4700 with "
        "forwarding-options sampling enabled causes FPC crashes. "
        "See https://supportportal.juniper.net/JSA88588"
    )
