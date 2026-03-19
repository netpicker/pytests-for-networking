import re
from comfy import high


@high(
    name='rule_cve202552958',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration protocols bgp | display set',
        show_config_validation='show configuration routing-options validation | display set'
    ),
)
def rule_cve202552958(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52958 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an adjacent, unauthenticated attacker to cause a DoS
    by triggering an rpd crash during BGP session establishment when route validation is enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = [
        # All versions before 22.2R3-S6
        '21.1', '21.2', '21.3', '21.4', '22.1', '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # 22.4 before 22.4R3-S6
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5',
        # 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # 23.4 before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # 24.2 before 24.2R2
        '24.2R1', '24.2R1-S1'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if BGP is configured
    bgp_config = commands.show_config_bgp
    has_bgp = 'protocols bgp' in bgp_config and bgp_config.strip() != ''

    if not has_bgp:
        return

    # Check if route validation is enabled
    validation_config = commands.show_config_validation
    has_validation = 'routing-options validation' in validation_config and validation_config.strip() != ''

    # Assert that the device is not vulnerable
    assert not has_validation, (
        f"Device {device.name} is vulnerable to CVE-2025-52958. "
        "The device is running a vulnerable version of Junos OS with BGP and route validation enabled, "
        "which makes it susceptible to rpd crashes during BGP session establishment failures. "
        "Continued session establishment failures can lead to a sustained DoS condition. "
        "For more information, see https://supportportal.juniper.net/JSA88958"
    )