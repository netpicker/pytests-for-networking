import re
from comfy import high

@high(
    name='rule_cve202521596',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
    ),
)
def rule_cve202521596(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-21596 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows a local, low-privileged attacker to cause a DoS condition
    by executing the 'show chassis environment pem' command that crashes the chassisd daemon
    on SRX1500, SRX4100, and SRX4200 devices.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.4R3-S9
        '21.2R1', '21.2R2', '21.2R3',
        '21.3R1', '21.3R2', '21.3R3',
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        # from 22.2 before 22.2R3-S5
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        # from 22.3 before 22.3R3-S4
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1', '22.3R3-S2', '22.3R3-S3',
        # from 22.4 before 22.4R3-S4
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3',
        # from 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # from 23.4 before 23.4R2-S1
        '23.4R1', '23.4R2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is SRX1500, SRX4100, or SRX4200
    chassis_output = commands.show_chassis_hardware
    is_vulnerable_platform = any(model in chassis_output for model in ['SRX1500', 'SRX4100', 'SRX4200'])

    if not is_vulnerable_platform:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-21596. "
        "The device is running a vulnerable version of Junos OS on SRX1500, SRX4100, or SRX4200 hardware, "
        "which makes it susceptible to chassisd crashes through execution of 'show chassis environment pem' command. "
        "Repeated execution can cause permanent chassisd failure and impact packet processing. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )