from comfy import medium

@medium(
    name='rule_cve202520190',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_lobby_admin='show running-config | count type lobby-admin',
        show_http_server='show running-config | include ip http server|secure|active'
    ),
)
def rule_cve202520190(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20190 vulnerability in Cisco IOS XE 
    Wireless Controller Software where an authenticated, remote attacker with lobby 
    ambassador credentials could remove arbitrary users including administrative users.

    The vulnerability is due to insufficient access control of actions executed by 
    lobby ambassador users. An attacker could exploit this by logging in with a lobby 
    ambassador account and sending crafted HTTP requests to the API.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions for Cisco IOS XE Wireless Controller
    # Based on the advisory, this affects Catalyst 9800 series and embedded wireless controllers
    # The advisory doesn't specify exact version numbers, so we check for IOS XE presence
    # and rely on configuration checks
    
    # Check if this is an IOS XE device
    if 'Cisco IOS XE Software' not in version_output:
        return

    # Check if lobby ambassador accounts are configured
    lobby_admin_output = commands.show_lobby_admin
    
    # Extract the count of lobby ambassador accounts
    lobby_admin_count = 0
    if 'Number of lines which match regexp' in lobby_admin_output:
        try:
            # Parse the count from output like "Number of lines which match regexp = 1"
            count_line = [line for line in lobby_admin_output.split('\n') if 'Number of lines which match regexp' in line][0]
            lobby_admin_count = int(count_line.split('=')[-1].strip())
        except (IndexError, ValueError):
            lobby_admin_count = 0

    # If no lobby ambassador accounts are configured, device is not vulnerable
    if lobby_admin_count == 0:
        return

    # Check if HTTP server is enabled (not disabled with "no")
    http_server_output = commands.show_http_server
    
    http_enabled = 'ip http server' in http_server_output and 'no ip http server' not in http_server_output
    https_enabled = 'ip http secure-server' in http_server_output and 'no ip http secure-server' not in http_server_output
    
    # Check for configurations that make the vulnerability not exploitable
    http_disabled_modules = 'ip http active-session-modules none' in http_server_output
    https_disabled_modules = 'ip http secure-active-session-modules none' in http_server_output
    
    # Determine if the device is vulnerable
    http_exploitable = http_enabled and not http_disabled_modules
    https_exploitable = https_enabled and not https_disabled_modules
    
    # If HTTP server is enabled and lobby ambassador accounts exist, device is vulnerable
    if (http_exploitable or https_exploitable) and lobby_admin_count > 0:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20190. "
            f"The device has {lobby_admin_count} lobby ambassador account(s) configured "
            "AND has HTTP/HTTPS server enabled without proper session module restrictions. "
            "An authenticated attacker with lobby ambassador credentials could delete arbitrary user accounts. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-user-del-hQxMpUDj"
        )
    
    return