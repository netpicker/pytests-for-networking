from comfy import high


@high(
    name='rule_cve202520190',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config',
        show_lobby_admin_count='show running-config | count type lobby-admin',
        show_http_config='show running-config | include ip http server|secure|active'
    ),
)
def rule_cve202520190(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20190 vulnerability in Cisco IOS XE Wireless Controller Software.
    The vulnerability allows an authenticated, remote attacker with lobby ambassador credentials to remove arbitrary
    users from the device due to insufficient access control. This affects Catalyst 9800 Series Wireless Controllers
    and Embedded Wireless Controllers.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE Wireless Controller Software
    # The vulnerability only affects IOS XE Wireless Controller Software on specific platforms
    is_wireless_controller = any(keyword in version_output for keyword in [
        'Catalyst 9800',
        '9800-CL',
        'Embedded Wireless Controller'
    ])

    # If not a wireless controller, device is not vulnerable
    if not is_wireless_controller:
        return

    # Check for lobby ambassador account configuration
    lobby_admin_output = commands.show_lobby_admin_count
    
    # Parse the count of lobby ambassador accounts
    # Expected format: "Number of lines which match regexp = X"
    lobby_admin_count = 0
    if 'Number of lines which match regexp' in lobby_admin_output:
        try:
            lobby_admin_count = int(lobby_admin_output.split('=')[-1].strip())
        except (ValueError, IndexError):
            lobby_admin_count = 0
    
    # Alternative check: look for lobby-admin in running config
    config_output = commands.show_running_config
    has_lobby_admin = 'type lobby-admin' in config_output or 'lobby-admin' in config_output or lobby_admin_count > 0

    # Check if HTTP server is enabled
    http_config_output = commands.show_http_config
    
    http_server_enabled = 'ip http server' in http_config_output
    https_server_enabled = 'ip http secure-server' in http_config_output
    
    # Check if HTTP/HTTPS is disabled via active-session-modules none
    http_disabled = 'ip http active-session-modules none' in config_output
    https_disabled = 'ip http secure-active-session-modules none' in config_output
    
    # Determine if HTTP/HTTPS is exploitable
    http_exploitable = http_server_enabled and not http_disabled
    https_exploitable = https_server_enabled and not https_disabled
    
    web_interface_enabled = http_exploitable or https_exploitable

    # Device is vulnerable if:
    # 1. It's a wireless controller (checked above)
    # 2. Lobby ambassador account is configured
    # 3. HTTP/HTTPS server is enabled and exploitable
    is_vulnerable = has_lobby_admin and web_interface_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20190. "
        "The device is running Cisco IOS XE Wireless Controller Software with lobby ambassador accounts configured "
        "and HTTP/HTTPS server enabled, which allows authenticated attackers to delete arbitrary user accounts. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-user-del-hQxMpUDj"
    )