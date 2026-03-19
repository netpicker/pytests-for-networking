from comfy import high


@high(
    name='rule_cve202520160',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config_tacacs='show running-config | include tacacs'
    ),
)
def rule_cve202520160(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20160 vulnerability in Cisco IOS and IOS XE Software.
    The vulnerability exists because the system does not properly check whether the required TACACS+ 
    shared secret is configured. An unauthenticated, remote attacker could exploit this vulnerability 
    by intercepting and reading unencrypted TACACS+ messages or impersonating the TACACS+ server and 
    falsely accepting arbitrary authentication requests.
    """
    # Extract the version and configuration information from the command output
    version_output = commands.show_version
    config_output = commands.show_running_config_tacacs

    # Check if TACACS+ is configured
    tacacs_configured = 'tacacs' in config_output.lower()

    # If TACACS+ is not configured, the device is not vulnerable
    if not tacacs_configured:
        return

    # Parse the configuration to check for TACACS+ servers and their keys
    config_lines = config_output.split('\n')
    
    # Check for global TACACS+ key
    global_key_configured = False
    for line in config_lines:
        if 'tacacs-server key' in line.lower():
            global_key_configured = True
            break
    
    # Track TACACS+ servers and their keys
    tacacs_servers = []
    server_keys = {}
    
    for line in config_lines:
        line = line.strip()
        if 'tacacs server' in line.lower() and 'tacacs-server' not in line.lower():
            # Extract server name
            parts = line.split()
            if len(parts) >= 3:
                server_name = parts[2]
                tacacs_servers.append(server_name)
                # Check if key is on the same line
                if 'key' in line.lower():
                    server_keys[server_name] = True
                else:
                    server_keys[server_name] = False
    
    # If there are TACACS+ servers configured
    if tacacs_servers:
        # Check if any server is missing a key
        vulnerable = False
        for server in tacacs_servers:
            # Server is vulnerable if it doesn't have a specific key and there's no global key
            if not server_keys.get(server, False) and not global_key_configured:
                vulnerable = True
                break
        
        # Assert that the device is not vulnerable
        assert not vulnerable, (
            f"Device {device.name} is vulnerable to CVE-2025-20160. "
            "The device has TACACS+ configured but one or more TACACS+ servers are missing "
            "the required shared secret configuration. This allows an unauthenticated, remote attacker "
            "to view sensitive data or bypass authentication. "
            "Ensure every TACACS+ server has a shared secret configured. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-tacacs-hdB7thJw"
        )