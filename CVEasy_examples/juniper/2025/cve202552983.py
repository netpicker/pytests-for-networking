import re
from comfy import high

@high(
    name='rule_cve202552983',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_system_login='show configuration system login | display set'
    ),
)
def rule_cve202552983(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52983 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows a network-based, unauthenticated attacker to access the device
    on VM Host systems where removed public keys for root still allow authentication.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = []
    
    # All versions before 22.2R3-S7
    vulnerable_versions.extend([
        '21.1', '21.2', '21.3', '21.4', '22.1', '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5', '22.2R3-S6'
    ])
    
    # 22.4 versions before 22.4R3-S5
    vulnerable_versions.extend([
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4'
    ])
    
    # 23.2 versions before 23.2R2-S3
    vulnerable_versions.extend([
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2'
    ])
    
    # 23.4 versions before 23.4R2-S3
    vulnerable_versions.extend([
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2'
    ])
    
    # 24.2 versions before 24.2R1-S2, 24.2R2
    vulnerable_versions.extend([
        '24.2R1', '24.2R1-S1'
    ])

    # Extract exact version token and check if it is vulnerable
    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ""
    version_vulnerable = version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is VM Host system
    chassis_output = commands.show_chassis_hardware
    is_vm_host = 'VM Host' in chassis_output or 'Virtual' in chassis_output or 'VMX' in chassis_output

    if not is_vm_host:
        return

    # Check if root user has SSH key authentication configured
    login_config = commands.show_system_login
    has_root_ssh_key = 'set system login user root authentication ssh-rsa' in login_config or \
                       'set system login user root authentication ssh-dsa' in login_config or \
                       'set system login user root authentication ssh-ecdsa' in login_config or \
                       'set system login user root authentication ssh-ed25519' in login_config or \
                       'set system login user root authentication load-key-file' in login_config

    # Assert that the device is not vulnerable
    assert not (is_vm_host and has_root_ssh_key), (
        f"Device {device.name} is vulnerable to CVE-2025-52983. "
        "The device is running a vulnerable version of Junos OS on VM Host systems "
        "where removed public keys for root can still allow authentication with the corresponding private key. "
        "This allows network-based, unauthenticated attackers to access the device. "
        "For more information, see https://supportportal.juniper.net/JSA88983"
    )