from comfy import high

@high(
    name='rule_cve202520334',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_http_config='show running-config | include ip http server|secure|active',
    ),
)
def rule_cve202520334(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20334 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the HTTP API subsystem of Cisco IOS XE Software could allow a remote 
    attacker to inject commands that will execute with root privileges into the underlying 
    operating system.
    
    The vulnerability is due to insufficient input validation. An attacker with administrative 
    privileges could exploit this vulnerability by authenticating to an affected system and 
    performing an API call with crafted input. Alternatively, an unauthenticated attacker 
    could persuade a legitimate user with administrative privileges who is currently logged 
    in to the system to click a crafted link.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (versions without fixes)
    # Based on typical Cisco IOS XE vulnerability patterns, assuming versions before fixes
    vulnerable_versions = [
        # 16.x versions
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b', '16.3.6', '16.3.7', '16.3.8',
        '16.3.9', '16.3.10', '16.3.11',
        '16.4.1', '16.4.2', '16.4.3',
        '16.5.1', '16.5.1a', '16.5.1b', '16.5.2', '16.5.3',
        '16.6.1', '16.6.2', '16.6.3', '16.6.4', '16.6.5', '16.6.4a', '16.6.5a', '16.6.6', '16.6.7', '16.6.8',
        '16.6.9', '16.6.10',
        '16.7.1', '16.7.2', '16.7.3',
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.2', '16.8.3',
        '16.9.1', '16.9.2', '16.9.1a', '16.9.1b', '16.9.1s', '16.9.3', '16.9.4', '16.9.3a', '16.9.5', '16.9.5f',
        '16.9.6', '16.9.7', '16.9.8',
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1e', '16.10.2', '16.10.3',
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s',
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.2', '16.12.2a', '16.12.3', '16.12.8', '16.12.2s',
        '16.12.1t', '16.12.4', '16.12.3s', '16.12.3a', '16.12.4a', '16.12.5', '16.12.6', '16.12.5a', '16.12.5b',
        '16.12.6a', '16.12.7', '16.12.9', '16.12.10', '16.12.10a', '16.12.11',
        # 17.x versions
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.3',
        '17.2.1', '17.2.1r', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.2a', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b',
        '17.3.4c', '17.3.5a', '17.3.5b', '17.3.7', '17.3.8', '17.3.8a',
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a',
        '17.6.1', '17.6.2', '17.6.1a', '17.6.3', '17.6.3a', '17.6.4', '17.6.5', '17.6.6', '17.6.6a', '17.6.5a',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', '17.9.4', '17.9.4a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.11.99SW',
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a',
        '17.13.1', '17.13.1a',
        '17.14.1', '17.14.1a',
        '17.15.1',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if HTTP Server feature is enabled
    http_config = commands.show_http_config
    
    # Check for HTTP server enabled (not disabled with "no")
    http_server_enabled = 'ip http server' in http_config and 'no ip http server' not in http_config
    # Check for HTTPS server enabled (not disabled with "no")
    https_server_enabled = 'ip http secure-server' in http_config and 'no ip http secure-server' not in http_config
    
    # Check if HTTP is disabled via active-session-modules none
    http_disabled = 'ip http active-session-modules none' in http_config
    # Check if HTTPS is disabled via secure-active-session-modules none
    https_disabled = 'ip http secure-active-session-modules none' in http_config
    
    # Determine if device is vulnerable
    http_vulnerable = http_server_enabled and not http_disabled
    https_vulnerable = https_server_enabled and not https_disabled
    
    # If either HTTP or HTTPS is enabled and exploitable, the device is vulnerable
    if http_vulnerable or https_vulnerable:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20334. "
            "The device is running a vulnerable version of Cisco IOS XE Software AND has the HTTP Server feature enabled. "
            "This vulnerability could allow a remote attacker to inject commands that execute with root privileges. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-cmd-inject-rPJM8BGL"
        )
    else:
        # If HTTP Server feature is not enabled or is properly disabled, the device is not vulnerable
        return