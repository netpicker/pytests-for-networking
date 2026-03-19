from comfy import high

@high(
    name='rule_cve202520172',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config'
    ),
)
def rule_cve202520172(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20172 vulnerability in Cisco IOS XR Software.
    The vulnerability in the SNMP subsystem could allow an authenticated, remote attacker to 
    cause the SNMP process to restart, resulting in an interrupted SNMP response.
    
    This vulnerability affects SNMP versions 1, 2c, and 3. Devices are vulnerable if they are
    running a vulnerable release with SNMP enabled.
    """

    # Extract the output of the commands
    show_version_output = commands.show_version or ''
    show_running_config_output = commands.show_running_config or ''

    # Fixed versions - at or above these are not vulnerable
    fixed_versions = [
        '24.2.21', '24.2.22', '24.2.23',
        '24.4.2', '24.4.3', '24.4.4',
        '25.2.1', '25.2.2', '25.3', '26.'
    ]
    
    # Check if running a fixed version first
    is_fixed = any(fixed in show_version_output for fixed in fixed_versions)
    if is_fixed:
        return

    # Define the vulnerable software versions based on the advisory
    # Versions before 24.2.21, 24.4.2, and 25.2.1 are vulnerable
    vulnerable_version_patterns = [
        # 24.2 and earlier (before 24.2.21)
        '24.2.1', '24.2.2', '24.2.3', '24.2.4', '24.2.5', '24.2.6', '24.2.7', '24.2.8', '24.2.9', '24.2.10',
        '24.2.11', '24.2.12', '24.2.13', '24.2.14', '24.2.15', '24.2.16', '24.2.17', '24.2.18', '24.2.19', '24.2.20',
        '24.1', '24.0',
        '23.', '22.', '21.', '20.', '19.', '18.', '17.', '16.', '15.', '14.', '13.', '12.', '11.', '10.',
        # 24.3 (all versions - migrate to fixed release)
        '24.3',
        # 24.4 before 24.4.2
        '24.4.1',
        # 25.2 before 25.2.1
        '25.2.0',
    ]

    # Check if the device's software version is vulnerable
    is_vulnerable_version = any(pattern in show_version_output for pattern in vulnerable_version_patterns)

    # Check if SNMP is enabled in the configuration
    snmp_enabled = False
    if 'snmp-server' in show_running_config_output:
        # Check for SNMP v1/v2c (community strings)
        if 'snmp-server community' in show_running_config_output:
            snmp_enabled = True
        # Check for SNMP v3 (groups and users)
        elif 'snmp-server group' in show_running_config_output:
            snmp_enabled = True

    # Device is vulnerable if running vulnerable version AND SNMP is enabled
    is_vulnerable = is_vulnerable_version and snmp_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20172. "
        f"The device is running a vulnerable version of Cisco IOS XR Software with SNMP enabled. "
        f"A successful exploit could allow an authenticated, remote attacker to cause the SNMP process to restart. "
        f"Please upgrade to a fixed release (24.2.21, 24.4.2, or 25.2.1) or disable SNMP if not required. "
        f"For more information and mitigations, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW"
    )