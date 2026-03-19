from comfy import high

@high(
    name='rule_cve202520312',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_wred_config='show running-config',
        show_snmp_community='show running-config | include snmp-server community',
        show_snmp_group='show running-config | include snmp-server group',
        show_snmp_user='show snmp user'
    ),
)
def rule_cve202520312(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20312 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the Simple Network Management Protocol (SNMP) subsystem could allow an
    authenticated, remote attacker to cause a denial of service (DoS) condition on an affected device.
    
    The vulnerability affects Cisco switches running vulnerable IOS XE Software with:
    - WRED for MPLS EXP configured (random-detect mpls-exp-based)
    - SNMP enabled (v1, v2c, or v3)
    
    Note: Cisco routing platforms do not support WRED for MPLS EXP and are not affected.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    
    # List of vulnerable software versions - this vulnerability affects all IOS XE versions
    # that support WRED for MPLS EXP on switches until fixed releases are available
    # Based on the advisory, we check for IOS XE Software presence
    is_ios_xe = 'Cisco IOS XE Software' in version_output
    
    if not is_ios_xe:
        return
    
    # Check if WRED for MPLS EXP is configured
    running_config = commands.show_wred_config
    wred_mpls_configured = 'random-detect mpls-exp-based' in running_config
    
    # If WRED for MPLS EXP is not configured, device is not vulnerable
    if not wred_mpls_configured:
        return
    
    # Check if the WRED policy is actually applied to an interface
    # Look for policy-map with random-detect mpls-exp-based and service-policy output
    wred_policy_applied = False
    if 'random-detect mpls-exp-based' in running_config and 'service-policy output' in running_config:
        # Parse to verify the policy with WRED is actually applied
        lines = running_config.split('\n')
        policy_maps = {}
        current_policy = None
        current_class = None
        
        for line in lines:
            line = line.strip()
            if line.startswith('policy-map '):
                current_policy = line.split('policy-map ')[1]
                policy_maps[current_policy] = {'has_wred': False}
            elif current_policy and 'random-detect mpls-exp-based' in line:
                policy_maps[current_policy]['has_wred'] = True
            elif 'service-policy output' in line:
                policy_name = line.split('service-policy output ')[1] if 'service-policy output ' in line else ''
                if policy_name in policy_maps and policy_maps[policy_name]['has_wred']:
                    wred_policy_applied = True
                    break
    
    if not wred_policy_applied:
        return
    
    # Check if SNMP is enabled (v1, v2c, or v3)
    snmp_community = commands.show_snmp_community
    snmp_group = commands.show_snmp_group
    snmp_user = commands.show_snmp_user
    
    # SNMPv1/v2c is enabled if community strings are configured
    snmpv1_v2c_enabled = 'snmp-server community' in snmp_community
    
    # SNMPv3 is enabled if both group and user are configured
    snmpv3_enabled = ('snmp-server group' in snmp_group and 
                      ('User name:' in snmp_user or 'Engine ID:' in snmp_user))
    
    snmp_enabled = snmpv1_v2c_enabled or snmpv3_enabled
    
    # If SNMP is not enabled, device is not vulnerable
    if not snmp_enabled:
        return
    
    # Device is vulnerable: has WRED for MPLS EXP configured and applied, and SNMP enabled
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-20312. "
        "The device is running Cisco IOS XE Software with WRED for MPLS EXP configured and applied, "
        "and SNMP is enabled. An authenticated attacker could send a specific SNMP request to cause "
        "the device to reload unexpectedly, resulting in a DoS condition. "
        "For more information and mitigation steps, see "
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmpwred-x3MJyf5M"
    )