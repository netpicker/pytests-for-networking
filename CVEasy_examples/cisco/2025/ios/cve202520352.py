from comfy import high


@high(
    name='rule_cve202520352',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include snmp-server',
        show_snmp_user='show snmp user'
    ),
)
def rule_cve202520352(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20352 vulnerability in Cisco IOS and IOS XE Software.
    The vulnerability is due to a stack overflow condition in the SNMP subsystem, which can be exploited
    by an authenticated, remote attacker to cause a denial of service (DoS) condition or execute arbitrary
    code as the root user. This vulnerability affects all versions of SNMP.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    
    # Check if this is Cisco IOS or IOS XE Software
    is_cisco_ios = 'Cisco IOS Software' in version_output or 'Cisco IOS XE Software' in version_output
    
    # If not Cisco IOS/IOS XE, device is not vulnerable
    if not is_cisco_ios:
        return
    
    # Check if SNMP is enabled
    config_output = commands.show_running_config
    snmp_user_output = commands.show_snmp_user
    
    # Check for SNMPv1/v2c community strings
    snmpv1v2_enabled = 'snmp-server community' in config_output
    
    # Check for SNMPv3 configuration
    snmpv3_enabled = 'snmp-server group' in config_output and snmp_user_output.strip() != ''
    
    # Device is vulnerable if any version of SNMP is enabled
    is_vulnerable = snmpv1v2_enabled or snmpv3_enabled
    
    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20352. "
        "The device is running Cisco IOS or IOS XE Software with SNMP enabled. "
        "This vulnerability affects all versions of SNMP and can allow an authenticated attacker "
        "to cause a DoS condition or execute arbitrary code as root. "
        "Upgrade to fixed software or apply the mitigation by excluding the affected OID (cafSessionMethodsInfoEntry). "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-x4LPhte"
    )