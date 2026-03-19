from comfy import high

@high(
    name='rule_cve202520169',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_snmp_community='show running-config | include snmp-server community',
        show_snmp_group='show running-config | include snmp-server group',
        show_snmp_user='show snmp user'
    ),
)
def rule_cve202520169(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20169: Cisco IOS XE Software SNMP Denial of Service Vulnerability.
    
    A vulnerability in the SNMP subsystem could allow an authenticated, remote attacker to cause
    a DoS condition by sending a crafted SNMP request that causes the device to reload unexpectedly.
    
    The vulnerability affects SNMP versions 1, 2c, and 3. The device is vulnerable if:
    - Running a vulnerable software version
    - SNMP is enabled (any version)
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions that need fixes
    vulnerable_versions = [
        # 15.2E - vulnerable until 15.2(7)E12
        '15.2(1)E', '15.2(2)E', '15.2(3)E', '15.2(4)E', '15.2(5)E', '15.2(6)E', '15.2(7)E',
        # 15.5SY - vulnerable until 15.5(1)SY15
        '15.5(1)SY',
        # 15.9M - vulnerable until 15.9(3)M11
        '15.9(3)M',
        # 3.11E - vulnerable until 3.11.12E
        '3.11.0E', '3.11.1E', '3.11.2E', '3.11.3E', '3.11.4E', '3.11.5E', '3.11.6E', '3.11.7E', '3.11.8E', '3.11.9E', '3.11.10E', '3.11.11E',
        # 16.12 - vulnerable until 16.12.13
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.2', '16.12.2a', '16.12.3', '16.12.8', '16.12.2s',
        '16.12.1t', '16.12.4', '16.12.3s', '16.12.3a', '16.12.4a', '16.12.5', '16.12.6', '16.12.5a', '16.12.5b',
        '16.12.6a', '16.12.7', '16.12.9', '16.12.10', '16.12.10a', '16.12.11', '16.12.12',
        # 17.9 - vulnerable until 17.9.7
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', '17.9.4', '17.9.4a', '17.9.5', '17.9.6',
        # 17.12 - vulnerable until 17.12.5
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a', '17.12.3', '17.12.4',
        # 17.15 - vulnerable until 17.15.3
        '17.15.1', '17.15.2'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SNMP v1 or v2c is enabled
    snmp_community_enabled = 'snmp-server community' in commands.show_snmp_community

    # Check if SNMP v3 is enabled
    snmp_group_enabled = 'snmp-server group' in commands.show_snmp_group
    snmp_user_output = commands.show_snmp_user
    snmp_v3_enabled = snmp_group_enabled and ('User name:' in snmp_user_output or 'Engine ID:' in snmp_user_output)

    # If any version of SNMP is enabled, the device is vulnerable
    if snmp_community_enabled or snmp_v3_enabled:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20169. "
            "The device is running a vulnerable version of Cisco IOS XE Software with SNMP enabled. "
            "An authenticated, remote attacker could send a crafted SNMP request to cause the device to reload unexpectedly. "
            "Upgrade to a fixed release or apply mitigations by disabling vulnerable OIDs. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW"
        )