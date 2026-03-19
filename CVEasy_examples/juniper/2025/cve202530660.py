import re
from comfy import high


@high(
    name='rule_cve202530660',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_gre='show configuration | display set | match "protocols gre"',
        show_interfaces_gre='show interfaces terse | match "gr-"'
    ),
)
def rule_cve202530660(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30660 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by sending a high rate of specific GRE traffic destined to the device, causing PFE hang.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # 21.4 versions before 21.4R3-S8
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7',
        # 22.2 versions before 22.2R3-S4
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        # 22.4 versions before 22.4R3-S5
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        # 23.2 versions before 23.2R2-S2
        '23.2R1', '23.2R2', '23.2R2-S1',
        # 23.4 versions before 23.4R2
        '23.4R1', '23.4R1-S1', '23.4R1-S2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is MX Series
    chassis_output = commands.show_chassis_hardware
    is_mx_platform = 'MX' in chassis_output

    if not is_mx_platform:
        return

    # Check if GRE is configured or GRE interfaces exist
    gre_config_output = commands.show_config_gre
    gre_interfaces_output = commands.show_interfaces_gre
    
    has_gre_config = 'protocols gre' in gre_config_output
    has_gre_interfaces = 'gr-' in gre_interfaces_output

    # Device is vulnerable if it has GRE configured or GRE interfaces
    is_vulnerable = has_gre_config or has_gre_interfaces

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-30660. "
        "The device is running a vulnerable version of Junos OS on MX Series hardware with GRE configured, "
        "which makes it susceptible to PFE hang through high rate of specific GRE traffic destined to the device. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )