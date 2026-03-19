from comfy import medium

@medium(
    name='rule_cve202520151',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_snmp_config='show running-config | include snmp-server user',
        show_snmp_users='show snmp user'
    ),
)
def rule_cve202520151(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20151 vulnerability in Cisco IOS XE Software.
    
    The vulnerability exists in SNMPv3 configuration where configuration lines exceeding 255
    characters may be truncated upon device reload, causing ACL restrictions to be bypassed.
    
    An authenticated, remote attacker with valid SNMPv3 credentials could poll the device
    even if configured to deny SNMP traffic from unauthorized sources.
    """
    # Extract the version information
    version_output = commands.show_version
    
    # Check if this is Cisco IOS XE
    if 'Cisco IOS XE Software' not in version_output:
        return
    
    # Check if SNMPv3 is configured
    snmp_config = commands.show_snmp_config
    
    if not snmp_config or 'snmp-server user' not in snmp_config:
        # No SNMPv3 configured, device is not vulnerable
        return
    
    # Parse SNMPv3 user configurations to check for potential truncation issues
    # Convert to string since commands may return a Source object
    snmp_users_output = str(commands.show_snmp_users or '')
    
    # Check for indicators of vulnerability:
    # 1. SNMPv3 users with authentication and privacy configured
    # 2. Access lists that might be truncated
    
    vulnerable_indicators = []
    
    # Check each line of SNMPv3 configuration
    for line in snmp_config.split('\n'):
        if 'snmp-server user' not in line:
            continue
            
        # Check if line has auth, priv, and access list configured
        has_auth = 'auth' in line and ('md5' in line or 'sha' in line)
        has_priv = 'priv' in line and ('des' in line or 'aes' in line or '3des' in line)
        has_access = 'access' in line
        
        if has_auth and has_priv and has_access:
            # Extract username and check if ACL is properly applied
            parts = line.split()
            if 'snmp-server' in parts and 'user' in parts:
                user_idx = parts.index('user')
                if user_idx + 1 < len(parts):
                    username = parts[user_idx + 1]
                    
                    # Check if this user's ACL is truncated in show snmp user output
                    user_marker = f'User name: {username}'
                    user_found = user_marker in snmp_users_output
                    
                    if user_found:
                        user_section = snmp_users_output[snmp_users_output.find(user_marker):]
                        has_access_list = 'access-list:' in user_section
                        
                        if has_access_list:
                            # Extract the ACL name from show snmp user
                            acl_line = [l for l in user_section.split('\n') if 'access-list:' in l]
                            if acl_line:
                                acl_from_show = acl_line[0].split('access-list:')[1].strip()
                                
                                # Extract the ACL name from configuration
                                # Handle both 'access ACL' and 'access ipv6 ACL' formats
                                if 'access' in line:
                                    access_idx = line.rfind('access')
                                    access_parts = line[access_idx:].split()
                                    if len(access_parts) > 1:
                                        # Skip 'ipv6' keyword if present
                                        acl_idx = 2 if access_parts[1] == 'ipv6' else 1
                                        acl_from_config = access_parts[acl_idx] if len(access_parts) > acl_idx else ''
                                    else:
                                        acl_from_config = ''
                                    
                                    # If ACL names don't match, it's likely truncated
                                    if acl_from_config and acl_from_show != acl_from_config:
                                        vulnerable_indicators.append(
                                            f"SNMPv3 user '{username}' has truncated ACL: "
                                            f"configured as '{acl_from_config}' but active as '{acl_from_show}'"
                                        )
    
    # Check for encrypted keyword which indicates stored configuration expansion
    if 'encrypted' in snmp_config:
        # Device has stored SNMPv3 config that may have been expanded
        # This is a strong indicator of potential vulnerability
        for line in snmp_config.split('\n'):
            if 'encrypted' in line and len(line) > 240:
                # Configuration line is close to or exceeds 255 character limit
                vulnerable_indicators.append(
                    "SNMPv3 configuration contains encrypted credentials with line length "
                    f"approaching 255 character limit ({len(line)} characters)"
                )
    
    # Assert vulnerability if indicators found
    if vulnerable_indicators:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20151. "
            "SNMPv3 configuration may be truncated upon reload, bypassing ACL restrictions. "
            f"Issues found: {'; '.join(vulnerable_indicators)}. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmpv3-qKEYvzsy"
        )