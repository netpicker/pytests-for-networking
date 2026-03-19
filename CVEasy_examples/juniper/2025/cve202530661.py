import re
from comfy import high


@high(
    name='rule_cve202530661',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_chassis_fpc='show chassis fpc'
    ),
)
def rule_cve202530661(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30661 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows a local, low-privileged user to install scripts to be 
    executed as root, leading to privilege escalation on specific line cards.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '23.2R1', '23.2R1-S1', '23.2R1-S2', '23.2R2', '23.2R2-S1', '23.2R2-S2', '23.2R2-S3',
        '23.4R1', '23.4R1-S1', '23.4R1-S2', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3', '23.4R2-S4',
        '24.2R1', '24.2R1-S1', '24.2R2',
        '24.4R1', '24.4R1-S1', '24.4R1-S2', '24.4R2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for vulnerable line cards
    chassis_output = commands.show_chassis_hardware
    fpc_output = commands.show_chassis_fpc

    # Combine outputs for checking
    combined_output = chassis_output + '\n' + fpc_output

    # Check for specific vulnerable line cards
    vulnerable_line_cards = [
        'MPC10', 'MPC11', 'LC4800', 'LC9600', 
        'MX304-LMIC16', 'SRX4700', 'EX9200-15C'
    ]

    has_vulnerable_line_card = any(line_card in combined_output 
                                   for line_card in vulnerable_line_cards)

    # Assert that the device is not vulnerable
    assert not has_vulnerable_line_card, (
        f"Device {device.name} is vulnerable to CVE-2025-30661. "
        "The device is running a vulnerable version of Junos OS with vulnerable line cards "
        "(MPC10, MPC11, LC4800, LC9600, MX304-LMIC16, SRX4700, or EX9200-15C), "
        "which allows a local, low-privileged user to execute scripts as root, leading to privilege escalation. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )