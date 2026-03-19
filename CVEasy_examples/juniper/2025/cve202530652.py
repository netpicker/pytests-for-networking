import re
from comfy import high

@high(
    name='rule_cve202530652',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_asregex=(
            'show configuration | display set | match asregex-optimized'
        )
    ),
)
def rule_cve202530652(configuration, commands, device, devices):
    """
    CVE-2025-30652: A local low-privileged attacker can crash rpd by running
    'show route as-path' when asregex-optimized is configured.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3',
        '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4',
        '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # from 21.4 before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4',
        '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # from 22.2 before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # from 22.4 before 22.4R3-S6
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5',
        # from 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # from 23.4 before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # from 24.2 before 24.2R2
        '24.2R1', '24.2R1-S1',
    ]

    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    if extracted_version not in vulnerable_versions:
        return

    # Check if asregex-optimized is configured
    config_output = commands.show_config_asregex
    config_lines = [
        line for line in config_output.splitlines()
        if not line.strip().startswith('#')
    ]
    has_asregex_optimized = any(
        'asregex-optimized' in line for line in config_lines
    )

    assert not has_asregex_optimized, (
        f"Device {device.name} is vulnerable to CVE-2025-30652. "
        "The device runs a vulnerable Junos OS with asregex-optimized "
        "configured, making it susceptible to rpd crashes via "
        "'show route as-path' CLI command. "
        "See https://supportportal.juniper.net/JSA88588"
    )
