import re
from comfy import high

@high(
    name='rule_cve202530654',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_configuration_system=(
            'show configuration system login | display set'
        ),
        show_cli_users='show cli authorization'
    ),
)
def rule_cve202530654(configuration, commands, device, devices):
    """
    CVE-2025-30654: A local low-privileged authenticated CLI user can access
    sensitive information (e.g. hashed passwords) via a specific show mgd
    command on vulnerable Junos OS and Junos OS Evolved versions.
    """
    version_output = commands.show_version

    # Vulnerable versions for Junos OS
    vulnerable_versions = [
        # All versions before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4',
        '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # from 22.2 before 22.2R3-S5
        '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        # from 22.4 before 22.4R3-S5
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        # from 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # from 23.4 before 23.4R2-S3
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2',
    ]

    # Vulnerable versions for Junos OS Evolved
    vulnerable_versions_evo = [
        # All versions before 21.4R3-S10-EVO
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO',
        '21.4R3-S1-EVO', '21.4R3-S2-EVO', '21.4R3-S3-EVO', '21.4R3-S4-EVO',
        '21.4R3-S5-EVO', '21.4R3-S6-EVO', '21.4R3-S7-EVO', '21.4R3-S8-EVO',
        '21.4R3-S9-EVO',
        # from 22.2-EVO before 22.2R3-S6-EVO
        '22.2R1-EVO', '22.2R2-EVO', '22.2R3-EVO',
        '22.2R3-S1-EVO', '22.2R3-S2-EVO', '22.2R3-S3-EVO',
        '22.2R3-S4-EVO', '22.2R3-S5-EVO',
        # from 22.4-EVO before 22.4R3-S5-EVO
        '22.4R1-EVO', '22.4R2-EVO', '22.4R3-EVO',
        '22.4R3-S1-EVO', '22.4R3-S2-EVO', '22.4R3-S3-EVO', '22.4R3-S4-EVO',
        # from 23.2-EVO before 23.2R2-S3-EVO
        '23.2R1-EVO', '23.2R2-EVO', '23.2R2-S1-EVO', '23.2R2-S2-EVO',
        # from 23.4-EVO before 23.4R2-S3-EVO
        '23.4R1-EVO', '23.4R2-EVO', '23.4R2-S1-EVO', '23.4R2-S2-EVO',
    ]

    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    all_vulnerable = vulnerable_versions + vulnerable_versions_evo
    if extracted_version not in all_vulnerable:
        return

    # Only flag if there are non-super-user login classes configured
    config_output = commands.show_configuration_system
    config_lines = [
        line for line in config_output.splitlines()
        if not line.strip().startswith('#')
    ]
    has_low_priv_users = any(
        'set system login' in line
        and 'class' in line
        and 'super-user' not in line
        for line in config_lines
    )

    assert not has_low_priv_users, (
        f"Device {device.name} is vulnerable to CVE-2025-30654. "
        "The device runs a vulnerable Junos OS/Evolved with non-super-user "
        "login classes configured. A local low-privileged CLI user can run "
        "specific show mgd commands to access sensitive data like hashed "
        "passwords. Fix: upgrade to 21.4R3-S10, 22.2R3-S5, 22.4R3-S5, "
        "23.2R2-S3, 23.4R2-S3 or later. "
        "See https://supportportal.juniper.net/JSA88888"
    )
