from comfy import high


@high(
    name='rule_cve202520221',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include snmp-server',
        show_sdwan_running='show sdwan running-config',
        show_snmp_user='show snmp user'
    ),
)
def rule_cve202520221(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20221 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability is due to improper traffic filtering conditions on an affected device, which could
    allow an unauthenticated, remote attacker to bypass Layer 3 and Layer 4 traffic filters and inject
    a crafted packet into the network.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE in Controller mode with SD-WAN
    is_ios_xe = 'IOS XE' in version_output or 'IOS-XE' in version_output
    
    # List of vulnerable universal IOS XE versions (17.2.1r and later with SD-WAN)
    vulnerable_universal_versions = [
        '17.2.1r', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.4', '17.3.5', '17.3.6',
        '17.4.1', '17.4.2',
        '17.5.1',
        '17.6.1', '17.6.2', '17.6.3', '17.6.4', '17.6.5',
        '17.7.1', '17.7.2',
        '17.8.1',
        '17.9.1', '17.9.2', '17.9.3', '17.9.4',
        '17.10.1',
        '17.11.1',
        '17.12.1', '17.12.2', '17.12.3',
        '17.13.1',
        '17.14.1',
        '17.15.1'
    ]
    
    # List of vulnerable standalone IOS XE SD-WAN versions
    vulnerable_standalone_versions = [
        '16.9.1', '16.9.2', '16.9.3', '16.9.4',
        '16.10.1', '16.10.2', '16.10.3', '16.10.4', '16.10.5',
        '16.11.1a',
        '16.12.2r', '16.12.3', '16.12.4'
    ]
    
    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = False
    
    if is_ios_xe:
        version_vulnerable = any(version in version_output for version in vulnerable_universal_versions)
    
    # Also check for standalone SD-WAN versions
    if not version_vulnerable:
        version_vulnerable = any(version in version_output for version in vulnerable_standalone_versions)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
    
    # Check if SD-WAN is enabled
    sdwan_output = commands.show_sdwan_running
    sdwan_enabled = 'sdwan' in sdwan_output.lower() or 'controller' in sdwan_output.lower()
    
    # If SD-WAN is not enabled, device is not vulnerable
    if not sdwan_enabled:
        return
    
    # Check if SNMP is enabled on the device
    config_output = commands.show_running_config
    snmp_user_output = commands.show_snmp_user
    
    # Check for SNMPv1/v2c (community strings)
    snmpv1v2_enabled = 'snmp-server community' in config_output
    
    # Check for SNMPv3 (requires both group and user configuration)
    snmpv3_group = 'snmp-server group' in config_output
    snmpv3_user = 'User name:' in snmp_user_output
    snmpv3_enabled = snmpv3_group and snmpv3_user
    
    # Device is vulnerable if SNMP is enabled on SD-WAN Tunnel interface
    snmp_enabled = snmpv1v2_enabled or snmpv3_enabled
    
    # If SNMP is not enabled, the device is not vulnerable
    if not snmp_enabled:
        return
    
    # Device is vulnerable: running vulnerable version, SD-WAN enabled, and SNMP enabled
    is_vulnerable = version_vulnerable and sdwan_enabled and snmp_enabled
    
    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20221. "
        "The device is running a vulnerable IOS XE SD-WAN version with SNMP enabled on SD-WAN Tunnel interfaces, "
        "which allows an unauthenticated, remote attacker to bypass Layer 3 and Layer 4 traffic filters. "
        "Workaround: Configure extended ACLs or device access policies to block unsolicited SNMP traffic. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn"
    )