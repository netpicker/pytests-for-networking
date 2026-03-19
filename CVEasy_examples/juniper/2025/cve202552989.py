import re
from comfy import high

@high(
    name='rule_cve202552989',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_annotate='show configuration | display set | match annotate',
        show_user_permissions='show configuration system login'
    ),
)
def rule_cve202552989(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52989 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows a local, authenticated attacker with high privileges to modify the system
    configuration using a specifically crafted annotate configuration command.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions for Junos OS
    vulnerable_versions = [
        # All versions before 22.2R3-S7
        '21.1', '21.2', '21.3', '21.4', '22.1', '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5', '22.2R3-S6',
        # 22.4 versions before 22.4R3-S7
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5', '22.4R3-S6',
        # 23.2 versions before 23.2R2-S4
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2', '23.2R2-S3',
        # 23.4 versions before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # 24.2 versions before 24.2R2-S1
        '24.2R1', '24.2R2',
        # 24.4 versions before 24.4R1-S2, 24.4R2
        '24.4R1', '24.4R1-S1'
    ]

    # Define vulnerable versions for Junos OS Evolved
    vulnerable_versions_evo = [
        # All versions before 22.4R3-S7-EVO
        '21.1-EVO', '21.2-EVO', '21.3-EVO', '21.4-EVO', '22.1-EVO', '22.2-EVO', '22.3-EVO',
        '22.4R1-EVO', '22.4R2-EVO', '22.4R3-EVO', '22.4R3-S1-EVO', '22.4R3-S2-EVO', '22.4R3-S3-EVO', '22.4R3-S4-EVO', '22.4R3-S5-EVO', '22.4R3-S6-EVO',
        # 23.2-EVO versions before 23.2R2-S4-EVO
        '23.2R1-EVO', '23.2R2-EVO', '23.2R2-S1-EVO', '23.2R2-S2-EVO', '23.2R2-S3-EVO',
        # 23.4-EVO versions before 23.4R2-S5-EVO
        '23.4R1-EVO', '23.4R2-EVO', '23.4R2-S1-EVO', '23.4R2-S2-EVO', '23.4R2-S3-EVO', '23.4R2-S4-EVO',
        # 24.2-EVO versions before 24.2R2-S1-EVO
        '24.2R1-EVO', '24.2R2-EVO',
        # 24.4-EVO versions before 24.4R2-EVO
        '24.4R1-EVO', '24.4R1-S1-EVO'
    ]

    # Extract exact version token and check if it is vulnerable
    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ""
    version_vulnerable = version in vulnerable_versions or version in vulnerable_versions_evo

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if there are users with limited configuration and commit permissions
    user_config = commands.show_user_permissions
    has_limited_users = 'class' in user_config and ('operator' in user_config or 'read-only' in user_config or 'unauthorized' in user_config)

    # The vulnerability exists if the device is running a vulnerable version
    # and has users with limited permissions who could exploit the annotate command
    is_vulnerable = version_vulnerable and has_limited_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-52989. "
        "The device is running a vulnerable version of Junos OS/Junos OS Evolved with users having limited "
        "configuration and commit permissions. These users can exploit the annotate configuration command "
        "to modify any part of the device configuration, bypassing permission restrictions. "
        "For more information, see https://supportportal.juniper.net/JSA88989"
    )