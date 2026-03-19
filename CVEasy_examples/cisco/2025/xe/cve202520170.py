from comfy import high

@high(
    name='rule_cve202520170',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_snmp_community='show running-config | include snmp-server community',
        show_snmp_group='show running-config | include snmp-server group',
        show_snmp_user='show snmp user'
    ),
)
def rule_cve202520170(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20170 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the SNMP subsystem could allow an authenticated, remote 
    attacker to cause a DoS condition by sending a crafted SNMP request that 
    causes the device to reload unexpectedly.
    
    The vulnerability affects SNMP versions 1, 2c, and 3 when SNMP is enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Fixed versions - at or above these are not vulnerable
    fixed_versions = [
        '16.12.13', '16.12.14', '16.12.15',
        '17.9.7', '17.9.8', '17.9.9',
        '17.12.5', '17.12.6', '17.12.7',
        '17.15.3', '17.15.4', '17.15.5',
        '18.'  # Major release 18.x is fixed
    ]
    
    # Check if running a fixed version first
    is_fixed = any(fixed in version_output for fixed in fixed_versions)
    if is_fixed:
        return

    # List of vulnerable software versions based on the advisory
    # Versions that need fixes as of March 2025
    vulnerable_versions = [
        # IOS XE 3.11E - vulnerable until 3.11.12E
        '3.11.0E', '3.11.1E', '3.11.2E', '3.11.3E', '3.11.4E', '3.11.5E', 
        '3.11.6E', '3.11.7E', '3.11.8E', '3.11.9E', '3.11.10E', '3.11.11E',
        # IOS XE 16.12 - vulnerable until 16.12.13
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.2', '16.12.2a', 
        '16.12.3', '16.12.8', '16.12.2s', '16.12.1t', '16.12.4', '16.12.3s', 
        '16.12.3a', '16.12.4a', '16.12.5', '16.12.6', '16.12.5a', '16.12.5b',
        '16.12.6a', '16.12.7', '16.12.9', '16.12.10', '16.12.10a', '16.12.11',
        '16.12.12',
        # IOS XE 17.9 - vulnerable until 17.9.7
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', 
        '17.9.4', '17.9.4a', '17.9.5', '17.9.6',
        # IOS XE 17.12 - vulnerable until 17.12.5
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a', '17.12.3', '17.12.4',
        # IOS XE 17.15 - vulnerable until 17.15.3
        '17.15.1', '17.15.2',
        # Additional vulnerable versions from other branches
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b', 
        '16.3.6', '16.3.7', '16.3.8', '16.3.9', '16.3.10', '16.3.11',
        '16.4.1', '16.4.2', '16.4.3',
        '16.5.1', '16.5.1a', '16.5.1b', '16.5.2', '16.5.3',
        '16.6.1', '16.6.2', '16.6.3', '16.6.4', '16.6.5', '16.6.4a', '16.6.5a', 
        '16.6.6', '16.6.7', '16.6.8', '16.6.9', '16.6.10',
        '16.7.1', '16.7.2', '16.7.3',
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.2', '16.8.3',
        '16.9.1', '16.9.2', '16.9.1a', '16.9.1b', '16.9.1s', '16.9.3', '16.9.4', 
        '16.9.3a', '16.9.5', '16.9.5f', '16.9.6', '16.9.7', '16.9.8',
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1e', '16.10.2', '16.10.3',
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s',
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.3',
        '17.2.1', '17.2.1r', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.2a', '17.3.4', '17.3.5', 
        '17.3.4a', '17.3.6', '17.3.4b', '17.3.4c', '17.3.5a', '17.3.5b', '17.3.7', 
        '17.3.8', '17.3.8a',
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a',
        '17.6.1', '17.6.2', '17.6.1a', '17.6.3', '17.6.3a', '17.6.4', '17.6.5', 
        '17.6.6', '17.6.6a', '17.6.5a',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.11.99SW',
        '17.13.1', '17.14.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SNMP is enabled (v1, v2c, or v3)
    snmp_community_output = commands.show_snmp_community
    snmp_group_output = commands.show_snmp_group
    snmp_user_output = commands.show_snmp_user

    # SNMP v1/v2c is enabled if there are community strings configured
    snmp_v1_v2c_enabled = 'snmp-server community' in snmp_community_output

    # SNMP v3 is enabled if there are groups and users configured
    snmp_v3_enabled = ('snmp-server group' in snmp_group_output and 
                       'User name:' in snmp_user_output)

    # If SNMP is enabled in any version, the device is vulnerable
    if snmp_v1_v2c_enabled or snmp_v3_enabled:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20170. "
            "The device is running a vulnerable version of Cisco IOS XE Software AND has SNMP enabled. "
            "An authenticated, remote attacker could send a crafted SNMP request to cause the device to reload, "
            "resulting in a denial of service condition. "
            "This vulnerability affects SNMP versions 1, 2c, and 3. "
            "For more information and mitigation steps, see "
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW"
        )