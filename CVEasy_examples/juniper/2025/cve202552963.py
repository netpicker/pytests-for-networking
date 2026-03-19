import re
from comfy import high

@high(
    name='rule_cve202552963',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_users='show configuration system login | display set'
    ),
)
def rule_cve202552963(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52963 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows a local, low-privileged attacker with "view" permissions
    to bring down an interface using a specific request interface command, leading to DoS.
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
    
    # From 21.4 before 21.4R3-S11
    vulnerable_versions.extend([
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        '21.4R3-S9', '21.4R3-S10'
    ])
    
    # From 22.2 before 22.2R3-S7
    vulnerable_versions.extend([
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.2R3-S4', '22.2R3-S5', '22.2R3-S6'
    ])
    
    # From 22.4 before 22.4R3-S7
    vulnerable_versions.extend([
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3',
        '22.4R3-S4', '22.4R3-S5', '22.4R3-S6'
    ])
    
    # From 23.2 before 23.2R2-S4
    vulnerable_versions.extend([
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2', '23.2R2-S3'
    ])
    
    # From 23.4 before 23.4R2-S5
    vulnerable_versions.extend([
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3', '23.4R2-S4'
    ])
    
    # From 24.2 before 24.2R2-S1
    vulnerable_versions.extend([
        '24.2R1', '24.2R2'
    ])
    
    # From 24.4 before 24.4R1-S3, 24.4R2
    vulnerable_versions.extend([
        '24.4R1', '24.4R1-S1', '24.4R1-S2', '24.4R2'
    ])

    # Extract exact version token and check if it is vulnerable
    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ""
    version_vulnerable = version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if there are users with view permissions configured
    users_config = commands.show_config_users
    has_view_users = 'class view' in users_config or 'permissions view' in users_config

    # Assert that the device is not vulnerable
    assert not has_view_users, (
        f"Device {device.name} is vulnerable to CVE-2025-52963. "
        "The device is running a vulnerable version of Junos OS and has users with 'view' permissions configured, "
        "which allows low-privileged attackers to bring down interfaces using specific request interface commands. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )