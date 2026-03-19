from comfy import high

@high(
    name='rule_cve202520160',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_tacacs_config='show running-config | include tacacs',
        show_tacacs_section='show running-config | section tacacs',
        show_tacacs_server_key='show running-config | include tacacs server|key'
    ),
)
def rule_cve202520160(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20160: Cisco IOS and IOS XE Software TACACS+ 
    Authentication Bypass Vulnerability.
    
    The vulnerability exists when TACACS+ is configured but the required shared 
    secret is missing. An unauthenticated, remote attacker could exploit this 
    to view sensitive data or bypass authentication.
    """
    # Check if TACACS+ is configured
    tacacs_config = commands.show_tacacs_config
    tacacs_section = commands.show_tacacs_section
    
    # If no TACACS+ configuration exists, device is not vulnerable
    if not tacacs_config and not tacacs_section:
        return
    
    # TACACS+ is configured, now check if all servers have shared secrets
    tacacs_server_key_output = commands.show_tacacs_server_key
    
    # Check for global TACACS+ key
    has_global_key = 'tacacs-server key' in tacacs_server_key_output
    
    # Extract all TACACS+ server lines
    lines = tacacs_server_key_output.split('\n')
    tacacs_servers = []
    server_keys = []
    
    for line in lines:
        line = line.strip()
        if line.startswith('tacacs server '):
            # Extract server name
            parts = line.split()
            if len(parts) >= 3:
                server_name = parts[2]
                tacacs_servers.append(server_name)
                # Check if this line has a key
                if ' key ' in line:
                    server_keys.append(server_name)
    
    # If there are TACACS+ servers configured
    if tacacs_servers:
        # Check if all servers have keys or if there's a global key
        if has_global_key:
            # Global key covers all servers
            return
        
        # Check if every server has an individual key
        servers_without_keys = [server for server in tacacs_servers if server not in server_keys]
        
        if servers_without_keys:
            assert False, (
                f"Device {device.name} is vulnerable to CVE-2025-20160. "
                f"TACACS+ is configured but the following servers are missing shared secrets: {', '.join(servers_without_keys)}. "
                "This could allow an unauthenticated attacker to bypass authentication or view sensitive data. "
                "Configure a shared secret for each TACACS+ server or use a global tacacs-server key. "
                "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-tacacs-hdB7thJw"
            )
    
    # Additional check: if TACACS+ config exists but no servers are explicitly defined
    # Check for older configuration style with just "aaa group server tacacs+"
    if 'aaa group server tacacs+' in tacacs_section or 'tacacs' in tacacs_config:
        # If we have TACACS+ references but couldn't find explicit servers with keys
        # and no global key, this is potentially vulnerable
        if not has_global_key and not tacacs_servers:
            # Check if there are any key configurations at all
            if 'key' not in tacacs_server_key_output and 'key' not in tacacs_section:
                assert False, (
                    f"Device {device.name} is vulnerable to CVE-2025-20160. "
                    "TACACS+ is configured but no shared secrets are configured. "
                    "This could allow an unauthenticated attacker to bypass authentication or view sensitive data. "
                    "Configure a shared secret for each TACACS+ server or use a global tacacs-server key. "
                    "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-tacacs-hdB7thJw"
                )