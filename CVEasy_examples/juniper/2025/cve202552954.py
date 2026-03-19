from comfy import high

@high(
    name='rule_cve202552954',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_routing_instances='show configuration routing-instances | display set',
        show_system_users='show system users'
    ),
)
def rule_cve202552954(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52954 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows a local, low-privileged user to gain root privileges through
    the internal virtual routing and forwarding (VRF), leading to system compromise.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Junos OS Evolved
    if 'Junos OS Evolved' not in version_output and 'EVO' not in version_output:
        return

    # Define the vulnerable version ranges
    vulnerable_versions = []
    
    # All versions before 22.2R3-S7-EVO
    vulnerable_versions.extend([
        '21.1', '21.2', '21.3', '21.4',
        '22.1', '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1-EVO', '22.2R3-S2-EVO', '22.2R3-S3-EVO', '22.2R3-S4-EVO', '22.2R3-S5-EVO', '22.2R3-S6-EVO'
    ])
    
    # from 22.4 before 22.4R3-S7-EVO
    vulnerable_versions.extend([
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1-EVO', '22.4R3-S2-EVO', '22.4R3-S3-EVO', '22.4R3-S4-EVO', '22.4R3-S5-EVO', '22.4R3-S6-EVO'
    ])
    
    # from 23.2 before 23.2R2-S4-EVO
    vulnerable_versions.extend([
        '23.2R1', '23.2R2',
        '23.2R2-S1-EVO', '23.2R2-S2-EVO', '23.2R2-S3-EVO'
    ])
    
    # from 23.4 before 23.4R2-S5-EVO
    vulnerable_versions.extend([
        '23.4R1', '23.4R2',
        '23.4R2-S1-EVO', '23.4R2-S2-EVO', '23.4R2-S3-EVO', '23.4R2-S4-EVO'
    ])
    
    # from 24.2 before 24.2R2-S1-EVO
    vulnerable_versions.extend([
        '24.2R1', '24.2R2'
    ])
    
    # from 24.4 before 24.4R1-S2-EVO, 24.4R2-EVO
    vulnerable_versions.extend([
        '24.4R1', '24.4R1-S1-EVO'
    ])

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for internal VRF configuration
    routing_instances_output = commands.show_config_routing_instances
    has_internal_vrf = 'routing-instances' in routing_instances_output and len(routing_instances_output.strip()) > 0

    # Check if there are low-privileged users on the system
    users_output = commands.show_system_users
    has_users = len(users_output.splitlines()) > 1  # More than just header

    # Device is vulnerable if running vulnerable version with VRF and users
    is_vulnerable = version_vulnerable and has_internal_vrf and has_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-52954. "
        "The device is running a vulnerable version of Junos OS Evolved with internal VRF configured, "
        "which allows a local, low-privileged user to gain root privileges and compromise the system. "
        "Any low-privileged user with the capability to send packets over the internal VRF can execute "
        "arbitrary Junos commands and modify the configuration. "
        "For more information, see https://supportportal.juniper.net/JSA88888"
    )