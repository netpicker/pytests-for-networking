import re
from comfy import high

@high(
    name='rule_cve202521592',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_aam=(
            'show configuration services advanced-anti-malware | display set'
        ),
        show_config_si=(
            'show configuration services security-intelligence | display set'
        )
    ),
)
def rule_cve202521592(configuration, commands, device, devices):
    """
    CVE-2025-21592: A local low-privileged user can view sensitive files via
    'show services advanced-anti-malware' or 'show services security-intelligence'
    on SRX Series devices running a vulnerable Junos OS version.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        # All versions before 21.4R3-S8
        '21.2R1', '21.2R2', '21.2R3',
        '21.3R1', '21.3R2', '21.3R3',
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4',
        '21.4R3-S5', '21.4R3-S6', '21.4R3-S7',
        # from 22.2 before 22.2R3-S5
        '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        # from 22.3 before 22.3R3-S3
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1', '22.3R3-S2',
        # from 22.4 before 22.4R3-S2
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1',
        # from 23.2 before 23.2R2-S1
        '23.2R1', '23.2R2',
        # from 23.4 before 23.4R2
        '23.4R1',
    ]

    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    if extracted_version not in vulnerable_versions:
        return

    # Check if device is SRX Series
    chassis_output = commands.show_chassis_hardware
    if 'SRX' not in chassis_output:
        return

    # Check if advanced-anti-malware or security-intelligence is configured
    aam_config = commands.show_config_aam
    si_config = commands.show_config_si

    aam_lines = [
        line for line in aam_config.splitlines()
        if not line.strip().startswith('#')
    ]
    si_lines = [
        line for line in si_config.splitlines()
        if not line.strip().startswith('#')
    ]
    has_aam = any('advanced-anti-malware' in line for line in aam_lines)
    has_si = any('security-intelligence' in line for line in si_lines)

    assert not (has_aam or has_si), (
        f"Device {device.name} is vulnerable to CVE-2025-21592. "
        "The device runs a vulnerable Junos OS on SRX Series hardware with "
        "advanced-anti-malware or security-intelligence services configured, "
        "allowing a local low-privileged user to view sensitive files via CLI. "
        "See https://supportportal.juniper.net/JSA88189"
    )
