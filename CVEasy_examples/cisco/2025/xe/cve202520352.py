from comfy import high

@high(
    name='rule_cve202520352',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_snmp_v1v2c='show running-config | include snmp-server community',
        show_snmp_group='show running-config | include snmp-server group',
        show_snmp_user='show snmp user',
        show_snmp_view='show running-config | include snmp-server view'
    ),
)
def rule_cve202520352(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20352 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the SNMP subsystem could allow an authenticated, remote attacker to:
    - With low privileges: cause a DoS condition by sending crafted SNMP packets
    - With high privileges: execute code as root user
    
    The vulnerability is due to a stack overflow condition in the SNMP subsystem.
    This affects all versions of SNMP (v1, v2c, v3).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Cisco IOS XE Software
    if 'Cisco IOS XE Software' not in version_output:
        return

    # Check if SNMPv1 or v2c is enabled
    snmp_v1v2c_enabled = bool(commands.show_snmp_v1v2c.strip())
    
    # Check if SNMPv3 is enabled (both group and user must be configured)
    snmp_group_configured = bool(commands.show_snmp_group.strip())
    snmp_user_configured = bool(commands.show_snmp_user.strip())
    snmp_v3_enabled = snmp_group_configured and snmp_user_configured
    
    # Check if any SNMP version is enabled
    snmp_enabled = snmp_v1v2c_enabled or snmp_v3_enabled
    
    if not snmp_enabled:
        # SNMP is not enabled, device is not vulnerable
        return
    
    # Check if mitigation is applied (cafSessionMethodsInfoEntry excluded)
    view_config = commands.show_snmp_view
    mitigation_applied = 'cafSessionMethodsInfoEntry excluded' in view_config
    
    if mitigation_applied:
        # Mitigation is applied, device is protected
        return
    
    # Device is vulnerable: SNMP is enabled and mitigation is not applied
    snmp_versions = []
    if snmp_v1v2c_enabled:
        snmp_versions.append('SNMPv1/v2c')
    if snmp_v3_enabled:
        snmp_versions.append('SNMPv3')
    
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-20352. "
        f"The device has SNMP enabled ({', '.join(snmp_versions)}) without proper mitigation. "
        "This vulnerability could allow authenticated attackers to cause DoS or execute arbitrary code as root. "
        "Apply the mitigation by excluding cafSessionMethodsInfoEntry OID from SNMP views or upgrade to fixed software. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-x4LPhte"
    )