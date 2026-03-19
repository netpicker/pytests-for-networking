import re
from comfy import high

@high(
    name='rule_cve202530645',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_dslite=(
            'show configuration | display set | match "softwire"'
        ),
        show_flowd_crashes='show system core-dumps | match flowd'
    ),
)
def rule_cve202530645(configuration, commands, device, devices):
    """
    CVE-2025-30645: Specific valid control traffic sent out of a DS-Lite
    tunnel can crash the flowd process on SRX Series devices, causing DoS.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3',
        '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4',
        '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # From 21.4 before 21.4R3-S9
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4',
        '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        # From 22.2 before 22.2R3-S5
        '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        # From 22.4 before 22.4R3-S6
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5',
        # From 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # From 23.4 before 23.4R2
        '23.4R1', '23.4R1-S1', '23.4R1-S2',
    ]

    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    if extracted_version not in vulnerable_versions:
        return

    # Check if device is SRX Series
    chassis_output = commands.show_chassis_hardware
    if 'SRX' not in chassis_output:
        return

    # Check if DS-Lite (softwire) is configured
    dslite_config = commands.show_config_dslite
    dslite_lines = [
        line for line in dslite_config.splitlines()
        if not line.strip().startswith('#')
    ]
    has_dslite_configured = any('softwire' in line for line in dslite_lines)

    assert not has_dslite_configured, (
        f"Device {device.name} is vulnerable to CVE-2025-30645. "
        "The device runs a vulnerable Junos OS on SRX Series hardware with "
        "DS-Lite tunnel (softwire) configured, making it susceptible to flowd "
        "process crashes through specific control traffic. "
        "See https://supportportal.juniper.net/JSA88588"
    )
