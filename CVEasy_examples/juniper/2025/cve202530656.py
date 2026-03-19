import re
from comfy import high


@high(
    name='rule_cve202530656',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_sip_alg='show configuration | display set | match "alg sip"'
    ),
)
def rule_cve202530656(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30656 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by sending specifically formatted SIP invites that cause memory corruption and FPC crashes
    when processed by the SIP ALG on MX Series with MS-MPC, MS-MIC and SPC3, and SRX Series.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # 21.4 versions before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # 22.2 versions before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # 22.4 versions before 22.4R3-S5
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        # 23.2 versions before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # 23.4 versions before 23.4R2-S3
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2',
        # 24.2 versions before 24.2R1-S2, 24.2R2
        '24.2R1', '24.2R1-S1', '24.2R2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is MX Series or SRX Series
    chassis_output = commands.show_chassis_hardware
    is_vulnerable_platform = 'MX' in chassis_output or 'SRX' in chassis_output

    if not is_vulnerable_platform:
        return

    # Check if SIP ALG is enabled
    sip_alg_config = commands.show_config_sip_alg
    sip_alg_enabled = 'alg sip' in sip_alg_config and 'alg sip disable' not in sip_alg_config

    # Assert that the device is not vulnerable
    assert not sip_alg_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-30656. "
        "The device is running a vulnerable version of Junos OS on MX Series or SRX Series hardware "
        "with SIP ALG enabled, which makes it susceptible to DoS attacks through specifically formatted SIP invites "
        "that cause memory corruption and FPC crashes. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )