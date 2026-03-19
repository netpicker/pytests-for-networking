from comfy import high


@high(
    name='rule_cve202520151',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_snmp_config='show running-config | include snmp-server user',
        show_startup_config='show startup-config | include snmp-server user'
    ),
)
def rule_cve202520151(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20151 vulnerability in Cisco IOS and IOS XE Software.
    The vulnerability exists in the SNMPv3 configuration implementation where configuration lines exceeding
    255 characters may be truncated upon device reload, causing ACL restrictions to be bypassed.
    """
    # Extract the configuration outputs
    snmp_config = commands.show_snmp_config
    startup_config = commands.show_startup_config

    # Check if SNMPv3 is configured
    snmpv3_configured = 'snmp-server user' in snmp_config and ' v3 ' in snmp_config

    # If SNMPv3 is not configured, device is not vulnerable
    if not snmpv3_configured:
        return

    # Check startup configuration for encrypted SNMPv3 entries with potential truncation
    # Look for lines with 'encrypted' keyword and 'access' keyword (indicating ACL usage)
    startup_lines = startup_config.split('\n')
    
    vulnerable_config_found = False
    truncated_acl_found = False
    
    for line in startup_lines:
        if 'snmp-server user' in line and ' v3 ' in line and 'encrypted' in line:
            # Check if line length exceeds 255 characters
            if len(line) > 255:
                vulnerable_config_found = True
                break
            
            # Check if line has 'access' keyword but appears truncated
            # (has 'access' but ACL name seems incomplete or missing)
            if 'access' in line:
                # Extract the part after 'access'
                access_index = line.find('access')
                after_access = line[access_index + 6:].strip()
                
                # If the ACL name after 'access' is very short (< 3 chars) or empty,
                # it might be truncated
                if len(after_access) < 3:
                    truncated_acl_found = True
                    break

    # Check running config for SNMPv3 users with ACLs that might be affected
    running_lines = snmp_config.split('\n')
    has_acl_config = False
    
    for line in running_lines:
        if 'snmp-server user' in line and ' v3 ' in line and 'access' in line:
            has_acl_config = True
            
            # Check if this configuration would exceed 255 chars when encrypted
            # Estimate: auth protocol adds ~59-143 chars, priv adds ~47-95 chars
            # If current line + estimated encryption overhead > 255, it's vulnerable
            
            # Count authentication and privacy protocols
            auth_overhead = 0
            priv_overhead = 0
            
            if 'auth md5' in line.lower():
                auth_overhead = 47
            elif 'auth sha' in line.lower() and 'sha-2 512' not in line.lower():
                auth_overhead = 59
            elif 'auth sha-2 256' in line.lower() or 'auth sha256' in line.lower():
                auth_overhead = 71
            elif 'auth sha-2 384' in line.lower() or 'auth sha384' in line.lower():
                auth_overhead = 95
            elif 'auth sha-2 512' in line.lower() or 'auth sha512' in line.lower():
                auth_overhead = 143
            
            if 'priv 3des' in line.lower():
                priv_overhead = 95
            elif 'priv aes 128' in line.lower():
                priv_overhead = 47
            elif 'priv aes 192' in line.lower():
                priv_overhead = 71
            elif 'priv aes 256' in line.lower():
                priv_overhead = 95
            
            # Estimate encrypted line length
            # Base line + auth overhead + priv overhead + 'encrypted' keyword (10 chars)
            estimated_length = len(line) + auth_overhead + priv_overhead + 10
            
            if estimated_length > 255:
                vulnerable_config_found = True
                break

    # Device is vulnerable if:
    # 1. SNMPv3 is configured with ACLs AND
    # 2. Configuration would exceed 255 characters when encrypted OR truncation detected
    is_vulnerable = has_acl_config and (vulnerable_config_found or truncated_acl_found)

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20151. "
        "The device has SNMPv3 configured with ACL restrictions, and the configuration line exceeds "
        "255 characters when stored in startup configuration. This may cause ACL names to be truncated "
        "upon device reload, allowing unauthorized SNMP access. "
        "Workaround: Move ACL to SNMPv3 group or shorten user/group/ACL names. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmpv3-qKEYvzsy"
    )