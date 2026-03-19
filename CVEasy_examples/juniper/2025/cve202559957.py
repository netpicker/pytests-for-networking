import re

from comfy import high


@high(
    name='rule_cve202559957',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_root=(
            'show configuration system root-authentication | display set'
        ),
    ),
)
def rule_cve202559957(configuration, commands, device, devices):
    """
    CVE-2025-59957: Origin Validation Error in Junos OS on EX4600/QFX5000.
    An unauthenticated attacker with physical access can create a backdoor
    by modifying /etc/config/<platform>-defaults[-flex].conf when no root
    password is configured.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        '21.4R1', '21.4R2',
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2',
    ]

    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ''
    if version not in vulnerable_versions:
        return

    chassis_output = commands.show_chassis_hardware
    is_vulnerable_platform = (
        'EX4600' in chassis_output
        or 'QFX5' in chassis_output
        or 'QFX5000' in chassis_output
    )
    if not is_vulnerable_platform:
        return

    root_config_output = commands.show_config_root
    has_root_password = (
        'encrypted-password' in root_config_output
        or 'plain-text-password' in root_config_output
    )

    assert has_root_password, (
        f"Device {device.name} is vulnerable to CVE-2025-59957. "
        "Running a vulnerable Junos OS version on EX4600 or QFX5000 "
        "without a root password allows an attacker with physical access "
        "to create a persistent backdoor. "
        "Upgrade to Junos OS 21.4R3, 22.2R3-S3 or later, or set a root "
        "password. "
        "See https://supportportal.juniper.net/JSA88125"
    )
