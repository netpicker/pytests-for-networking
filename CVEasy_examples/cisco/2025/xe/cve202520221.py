from comfy import medium

@medium(
    name='rule_cve202520221',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_snmp_community='show running-config | include snmp-server community',
        show_snmp_group='show running-config | include snmp-server group',
        show_snmp_user='show snmp user',
        show_sdwan='show sdwan running-config'
    ),
)
def rule_cve202520221(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20221: Cisco IOS XE SD-WAN Software Packet 
    Filtering Bypass Vulnerability.
    
    The vulnerability affects Cisco IOS XE Software running in Controller mode
    (releases 17.2.1r and later) or standalone SD-WAN releases, when SNMP is
    enabled on any SD-WAN Tunnel interface. An unauthenticated, remote attacker
    could bypass Layer 3 and Layer 4 traffic filters by sending crafted packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Universal Cisco IOS XE Software releases 17.2.1r and later in Controller mode
    universal_vulnerable_versions = [
        '17.2.1r', '17.2.1', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.2a', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b',
        '17.3.4c', '17.3.5a', '17.3.5b', '17.3.7', '17.3.8', '17.3.8a',
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a',
        '17.6.1', '17.6.2', '17.6.1a', '17.6.3', '17.6.3a', '17.6.4', '17.6.5', '17.6.6', '17.6.6a', '17.6.5a',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', '17.9.4', '17.9.4a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.11.99SW',
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a',
        '17.13.1', '17.13.1a',
        '17.14.1', '17.14.1a',
        '17.15.1'
    ]

    # Standalone Cisco IOS XE SD-WAN Software releases
    standalone_vulnerable_versions = [
        '16.9.1', '16.9.2', '16.9.3', '16.9.4',
        '16.10.1', '16.10.2', '16.10.3', '16.10.4', '16.10.5',
        '16.11.1a',
        '16.12.2r', '16.12.3', '16.12.4'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in universal_vulnerable_versions + standalone_vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SD-WAN is enabled
    sdwan_output = commands.show_sdwan
    sdwan_enabled = sdwan_output and 'sdwan' in sdwan_output.lower()

    # If SD-WAN is not enabled, device is not vulnerable
    if not sdwan_enabled:
        return

    # Check if SNMP is enabled (SNMPv1, SNMPv2c, or SNMPv3)
    snmp_community_output = commands.show_snmp_community
    snmp_group_output = commands.show_snmp_group
    snmp_user_output = commands.show_snmp_user

    # SNMPv1 or SNMPv2c is enabled if there's a community string configured
    snmpv1_v2c_enabled = snmp_community_output and 'snmp-server community' in snmp_community_output

    # SNMPv3 is enabled if both group and user are configured
    snmpv3_enabled = (snmp_group_output and 'snmp-server group' in snmp_group_output and 
                      snmp_user_output and 'User name:' in snmp_user_output)

    snmp_enabled = snmpv1_v2c_enabled or snmpv3_enabled

    # If SNMP is enabled on a device with SD-WAN, the device is vulnerable
    assert not snmp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-20221. "
        "The device is running a vulnerable IOS XE SD-WAN version with SNMP enabled. "
        "An unauthenticated, remote attacker could bypass Layer 3 and Layer 4 traffic filters. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn"
    )