import re
from comfy import high

@high(
    name='rule_cve202521590',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_cli_authorization='show configuration system login | display set | match "class"',
        show_users='show system users'
    ),
)
def rule_cve202521590(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-21590 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows a local attacker with high privileges and shell access
    to inject arbitrary code and compromise the integrity of the device.
    This issue is not exploitable from the Junos CLI.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = []
    
    # All versions before 21.2R3-S9
    vulnerable_versions.extend([
        '21.2R1', '21.2R2', '21.2R3',
        '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8'
    ])
    
    # 21.4 versions before 21.4R3-S10
    vulnerable_versions.extend([
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9'
    ])
    
    # 22.2 versions before 22.2R3-S6
    vulnerable_versions.extend([
        '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5'
    ])
    
    # 22.4 versions before 22.4R3-S6
    vulnerable_versions.extend([
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5'
    ])
    
    # 23.2 versions before 23.2R2-S3
    vulnerable_versions.extend([
        '23.2R1', '23.2R2',
        '23.2R2-S1', '23.2R2-S2'
    ])
    
    # 23.4 versions before 23.4R2-S4
    vulnerable_versions.extend([
        '23.4R1', '23.4R2',
        '23.4R2-S1', '23.4R2-S2', '23.4R2-S3'
    ])
    
    # 24.2 versions before 24.2R1-S2, 24.2R2
    vulnerable_versions.extend([
        '24.2R1', '24.2R1-S1', '24.2R2'
    ])

    # Extract exact version token and check if it is vulnerable
    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ""
    version_vulnerable = version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if there are users with shell access (high privilege requirement)
    cli_auth_output = commands.show_cli_authorization
    users_output = commands.show_users
    
    # Check for super-user or root class users who could have shell access
    has_privileged_users = any(keyword in cli_auth_output.lower() for keyword in ['super-user', 'superuser', 'root'])
    
    # Check if there are active user sessions
    has_active_users = 'root' in users_output or len(users_output.splitlines()) > 1

    # Device is vulnerable if running vulnerable version and has privileged users with potential shell access
    is_vulnerable = version_vulnerable and has_privileged_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-21590. "
        "The device is running a vulnerable version of Junos OS with privileged users who may have shell access. "
        "A local attacker with high privileges and shell access can inject arbitrary code to compromise device integrity. "
        "This issue is not exploitable from the Junos CLI. "
        "For more information, see https://supportportal.juniper.net/JSA88189"
    )