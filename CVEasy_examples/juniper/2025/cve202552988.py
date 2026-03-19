import re
from comfy import high

@high(
    name='rule_cve202552988',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_cli_users='show cli authorization',
        show_system_users='show system users'
    ),
)
def rule_cve202552988(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52988 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows a high privileged, local attacker to escalate their privileges to root
    through OS command injection in the 'request system logout' command.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = []
    
    # All versions before 21.2R3-S9
    vulnerable_versions.extend([
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', 
        '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8'
    ])
    
    # 21.4 versions before 21.4R3-S8
    vulnerable_versions.extend([
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7'
    ])
    
    # 22.2 versions before 22.2R3-S6
    vulnerable_versions.extend([
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.2R3-S4', '22.2R3-S5'
    ])
    
    # 22.3 versions before 22.3R3-S3
    vulnerable_versions.extend([
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1', '22.3R3-S2'
    ])
    
    # 22.4 versions before 22.4R3-S6
    vulnerable_versions.extend([
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3',
        '22.4R3-S4', '22.4R3-S5'
    ])
    
    # 23.2 versions before 23.2R2-S1
    vulnerable_versions.extend([
        '23.2R1', '23.2R2'
    ])
    
    # 23.4 versions before 23.4R1-S2, 23.4R2
    vulnerable_versions.extend([
        '23.4R1', '23.4R1-S1'
    ])
    
    # Junos OS Evolved versions
    # All versions before 22.4R3-S6-EVO
    vulnerable_versions.extend([
        '22.4R1-EVO', '22.4R2-EVO', '22.4R3-EVO', '22.4R3-S1-EVO', '22.4R3-S2-EVO',
        '22.4R3-S3-EVO', '22.4R3-S4-EVO', '22.4R3-S5-EVO'
    ])
    
    # 23.2-EVO versions before 23.2R2-S1-EVO
    vulnerable_versions.extend([
        '23.2R1-EVO', '23.2R2-EVO'
    ])
    
    # 23.4-EVO versions before 23.4R1-S2-EVO, 23.4R2-EVO
    vulnerable_versions.extend([
        '23.4R1-EVO', '23.4R1-S1-EVO'
    ])

    # Extract exact version token and check if it is vulnerable
    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ""
    version_vulnerable = version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if there are high privileged users (this vulnerability requires high privileges)
    # The vulnerability is exploitable by any high privileged local user
    cli_users_output = commands.show_cli_users
    system_users_output = commands.show_system_users
    
    # If there are users with CLI access, the device is potentially vulnerable
    has_cli_users = cli_users_output and len(cli_users_output.strip()) > 0
    has_system_users = system_users_output and len(system_users_output.strip()) > 0

    # Assert that the device is not vulnerable
    assert not (version_vulnerable and (has_cli_users or has_system_users)), (
        f"Device {device.name} is vulnerable to CVE-2025-52988. "
        "The device is running a vulnerable version of Junos OS or Junos OS Evolved "
        "that allows high privileged local attackers to escalate privileges to root "
        "through OS command injection in the 'request system logout' command. "
        "This can completely compromise the device. "
        "For more information, see https://supportportal.juniper.net/JSA88988"
    )