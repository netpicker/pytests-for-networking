import re
from comfy import high

@high(
    name='rule_cve202530647',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_subscriber='show configuration | display set | match "access profile"',
        show_chassis_fpc='show chassis fpc'
    ),
)
def rule_cve202530647(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30647 vulnerability in Juniper Networks Junos OS.
    A Missing Release of Memory after Effective Lifetime vulnerability in the packet 
    forwarding engine (PFE) allows an unauthenticated adjacent attacker to cause a 
    Denial-of-Service (DoS) in a subscriber management scenario.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # from 21.4 before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # from 22.2 before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # from 22.4 before 22.4R3-S5
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        # from 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # from 23.4 before 23.4R2-S3
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2',
        # from 24.2 before 24.2R2
        '24.2R1', '24.2R1-S1', '24.2R1-S2'
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

    # Check for subscriber management configuration
    config_output = commands.show_config_subscriber
    has_subscriber_management = 'access profile' in config_output

    # Check FPC status for potential memory issues
    fpc_output = commands.show_chassis_fpc
    has_online_fpc = 'Online' in fpc_output

    # Assert that the device is not vulnerable
    assert not (has_subscriber_management and has_online_fpc), (
        f"Device {device.name} is vulnerable to CVE-2025-30647. "
        "The device is running a vulnerable version of Junos OS on MX Series hardware with subscriber management configured, "
        "which makes it susceptible to memory leaks in the PFE during subscriber login/logout activity, eventually causing a crash. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )