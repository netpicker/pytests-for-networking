from comfy import high

@high(
    name='rule_cve202520174',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_snmp_community='show running-config | include snmp-server community',
        show_snmp_group='show running-config | include snmp-server group',
        show_snmp_user='show snmp user'
    ),
)
def rule_cve202520174(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20174 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the SNMP subsystem could allow an authenticated, remote 
    attacker to cause a DoS condition on an affected device. This vulnerability 
    is due to improper error handling when parsing SNMP requests.
    
    The vulnerability affects SNMP versions 1, 2c, and 3. An attacker must have
    valid SNMP credentials (community string or user credentials) to exploit.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions based on the advisory
    # Versions that will be fixed in March 2025
    vulnerable_versions = [
        # 3.11E - fixed in 3.11.12E
        '3.11.0E', '3.11.1E', '3.11.2E', '3.11.3E', '3.11.4E', '3.11.5E', 
        '3.11.6E', '3.11.7E', '3.11.8E', '3.11.9E', '3.11.10E', '3.11.11E',
        # 16.12 - fixed in 16.12.13
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.2', '16.12.2a', 
        '16.12.3', '16.12.8', '16.12.2s', '16.12.1t', '16.12.4', '16.12.3s', 
        '16.12.3a', '16.12.4a', '16.12.5', '16.12.6', '16.12.5a', '16.12.5b',
        '16.12.6a', '16.12.7', '16.12.9', '16.12.10', '16.12.10a', '16.12.11',
        '16.12.12',
        # 17.9 - fixed in 17.9.7
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', 
        '17.9.4', '17.9.4a', '17.9.5', '17.9.6',
        # 17.12 - fixed in 17.12.5
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a', '17.12.3', '17.12.4',
        # 17.15 - fixed in 17.15.3
        '17.15.1', '17.15.2',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SNMP is enabled (v1/v2c)
    snmp_community_enabled = 'snmp-server community' in commands.show_snmp_community
    
    # Check if SNMP v3 is enabled
    snmp_group_output = commands.show_snmp_group
    snmp_user_output = commands.show_snmp_user
    snmp_v3_enabled = ('snmp-server group' in snmp_group_output and 
                       'User name:' in snmp_user_output)

    # If SNMP is enabled (any version), the device is vulnerable
    if snmp_community_enabled or snmp_v3_enabled:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20174. "
            "The device is running a vulnerable version of Cisco IOS XE Software AND has SNMP enabled. "
            "This vulnerability in the SNMP subsystem could allow an authenticated, remote attacker "
            "to cause a DoS condition by sending crafted SNMP requests. "
            "Upgrade to a fixed release or apply mitigations from the advisory. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW"
        )
    else:
        # If SNMP is not enabled, the device is not vulnerable
        return