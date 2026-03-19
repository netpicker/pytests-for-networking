from comfy import high

@high(
    name='rule_cve202520186',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_lobby_admin='show running-config | count type lobby-admin',
        show_http_server='show running-config | include ip http server|secure|active',
        show_aaa='show running-config | section aaa'
    ),
)
def rule_cve202520186(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20186 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the web-based management interface of the Wireless LAN Controller feature
    could allow an authenticated, remote attacker with a lobby ambassador user account to perform
    a command injection attack against an affected device.
    
    The vulnerability affects devices that have:
    1. A lobby ambassador account configured
    2. HTTP server feature enabled (ip http server or ip http secure-server)
    
    Affected products:
    - Catalyst 9800-CL Wireless Controllers for Cloud
    - Catalyst 9800 Embedded Wireless Controller for Catalyst 9300, 9400, and 9500 Series Switches
    - Catalyst 9800 Series Wireless Controllers
    - Embedded Wireless Controller on Catalyst 9100X Series Access Points
    - Integrated access points (APs) in ISR1100 (Wi-Fi 6)
    - Wi-Fi 6 pluggable module for Catalyst IR1800 Rugged Series Routers
    """
    
    # Extract version information
    version_output = commands.show_version
    
    # Check if device is an affected product type
    # Check for both "C9800" format and "Catalyst 9800" format
    affected_products = [
        'C9800', '9800',  # Catalyst 9800 series
        'C9300', '9300',  # Catalyst 9300 with embedded WLC
        'C9400', '9400',  # Catalyst 9400 with embedded WLC
        'C9500', '9500',  # Catalyst 9500 with embedded WLC
        'C9100', '9100',  # Catalyst 9100X series
        'ISR1100',  # ISR1100 series
        'IR1800'  # IR1800 series
    ]
    
    # Also check for "Wireless Controller" in version to identify WLC devices
    is_wireless_controller = 'Wireless Controller' in version_output
    is_affected_product = any(product in version_output for product in affected_products) and is_wireless_controller
    
    # If not an affected product type, device is not vulnerable
    if not is_affected_product:
        return
    
    # Check for lobby ambassador account configuration
    lobby_admin_output = commands.show_lobby_admin
    
    # Parse the count of lobby-admin accounts
    lobby_admin_count = 0
    if 'Number of lines which match regexp' in lobby_admin_output:
        try:
            # Extract the number from output like "Number of lines which match regexp =  1"
            lobby_admin_count = int(lobby_admin_output.split('=')[-1].strip())
        except (ValueError, IndexError):
            lobby_admin_count = 0
    
    # Check for AAA configuration that might have lobby-admin role
    aaa_output = commands.show_aaa
    has_aaa_lobby_admin = 'lobby-admin' in aaa_output or 'cisco-av-pair=lobby-admin' in aaa_output
    
    # If no lobby ambassador account is configured, device is not vulnerable
    if lobby_admin_count == 0 and not has_aaa_lobby_admin:
        return
    
    # Check if HTTP server is enabled
    http_output = commands.show_http_server
    
    # Check for enabled HTTP servers (not disabled with 'no' prefix)
    http_lines = http_output.splitlines()
    http_enabled = any(
        line.strip() == 'ip http server' or line.strip().startswith('ip http server ')
        for line in http_lines
    )
    https_enabled = any(
        line.strip() == 'ip http secure-server' or line.strip().startswith('ip http secure-server ')
        for line in http_lines
    )
    
    # Check for mitigation configurations
    http_mitigated = http_enabled and 'ip http active-session-modules none' in http_output
    https_mitigated = https_enabled and 'ip http secure-active-session-modules none' in http_output
    
    # Determine if device is vulnerable
    is_vulnerable = False
    
    if http_enabled and not http_mitigated:
        is_vulnerable = True
    
    if https_enabled and not https_mitigated:
        is_vulnerable = True
    
    # Assert if device is vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20186. "
        f"The device has a lobby ambassador account configured ({lobby_admin_count} account(s) found) "
        f"AND has HTTP/HTTPS server enabled without proper mitigation. "
        f"This allows an authenticated attacker with lobby ambassador credentials to execute arbitrary "
        f"CLI commands with privilege level 15. "
        f"For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-cmdinj-gVn3OKNC"
    )