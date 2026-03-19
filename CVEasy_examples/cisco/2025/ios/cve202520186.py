from comfy import high


@high(
    name='rule_cve202520186',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config',
        show_lobby_admin='show running-config | count type lobby-admin',
        show_http_server='show running-config | include ip http server|secure|active'
    ),
)
def rule_cve202520186(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20186 vulnerability in Cisco IOS XE Software.
    The vulnerability is in the web-based management interface of the Wireless LAN Controller feature
    and could allow an authenticated, remote attacker with a lobby ambassador user account to perform
    a command injection attack and execute arbitrary CLI commands with privilege level 15.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE Software (vulnerability only affects IOS XE)
    if 'IOS XE' not in version_output:
        return

    # Check if device is an affected product type
    affected_products = [
        'Catalyst 9800',
        'C9800',
        '9800',
        'Catalyst 9300',
        'Catalyst 9400',
        'Catalyst 9500',
        'Catalyst 9100',
        'ISR1100',
        'IR1800'
    ]
    
    is_affected_product = any(product in version_output for product in affected_products)
    
    # If not an affected product, no need to check further
    if not is_affected_product:
        return

    # Check for lobby ambassador account configuration
    lobby_admin_output = commands.show_lobby_admin
    config_output = commands.show_running_config
    
    # Check if lobby ambassador account is configured
    # Either through local config or potentially through AAA
    has_lobby_admin = False
    
    if 'Number of lines which match regexp' in lobby_admin_output:
        # Extract the count from the output
        try:
            count_line = [line for line in lobby_admin_output.split('\n') if 'Number of lines' in line][0]
            count = int(count_line.split('=')[-1].strip())
            if count > 0:
                has_lobby_admin = True
        except (IndexError, ValueError):
            pass
    
    # Also check for lobby-admin in the running config directly
    if 'type lobby-admin' in config_output or 'lobby-admin' in config_output:
        has_lobby_admin = True
    
    # Check for AAA configuration that might use lobby ambassador role
    if 'cisco-av-pair=lobby-admin' in config_output:
        has_lobby_admin = True
    
    # If no lobby ambassador account is configured, device is not vulnerable
    if not has_lobby_admin:
        return

    # Check if HTTP server is enabled
    http_server_output = commands.show_http_server
    
    http_enabled = 'ip http server' in http_server_output
    https_enabled = 'ip http secure-server' in http_server_output
    
    # Check for mitigation configurations
    http_mitigated = 'ip http active-session-modules none' in config_output
    https_mitigated = 'ip http secure-active-session-modules none' in config_output
    
    # Determine if vulnerability is exploitable
    is_vulnerable = False
    
    if http_enabled and not http_mitigated:
        is_vulnerable = True
    
    if https_enabled and not https_mitigated:
        is_vulnerable = True
    
    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20186. "
        "The device is running Cisco IOS XE Software with a lobby ambassador account configured "
        "AND has the HTTP server feature enabled without proper mitigation, "
        "which makes it susceptible to command injection attacks allowing privilege level 15 access. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-cmdinj-gVn3OKNC"
    )