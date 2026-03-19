import re

from comfy import high


@high(
    name='rule_cve20256549',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_jweb=(
            'show configuration system services web-management | display set'
        ),
        show_config_jsc=(
            'show configuration system services juniper-secure-connect'
            ' | display set'
        ),
    ),
)
def rule_cve20256549(configuration, commands, device, devices):
    """
    CVE-2025-6549: Unauthenticated attacker can reach J-Web UI when JSC
    is enabled on specific interfaces or multiple interfaces are configured
    for J-Web on SRX Series.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        '23.4R1', '23.4R2',
        '23.4R2-S1', '23.4R2-S2', '23.4R2-S3', '23.4R2-S4',
        '24.2R1', '24.2R1-S1', '24.2R1-S2',
    ]

    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ''
    if version not in vulnerable_versions:
        return

    chassis_output = commands.show_chassis_hardware
    if 'SRX' not in chassis_output and 'srx' not in chassis_output.lower():
        return

    jweb_config = commands.show_config_jweb
    jweb_enabled = (
        'set system services web-management' in jweb_config
        and jweb_config.strip() != ''
    )

    jsc_config = commands.show_config_jsc
    jsc_enabled = (
        'set system services juniper-secure-connect' in jsc_config
        and jsc_config.strip() != ''
    )

    jweb_interface_count = jweb_config.count('interface')
    multiple_jweb_interfaces = jweb_interface_count > 1

    is_vulnerable = jweb_enabled and (jsc_enabled or multiple_jweb_interfaces)

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-6549. "
        "Running a vulnerable Junos OS version on SRX with J-Web enabled "
        "and JSC enabled or multiple J-Web interfaces allows unauthenticated "
        "access to J-Web over unintended interfaces. "
        "See https://supportportal.juniper.net/JSA88549"
    )
