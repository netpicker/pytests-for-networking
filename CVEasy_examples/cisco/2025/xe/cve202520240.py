from comfy import medium

@medium(
    name='rule_cve202520240',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_http_config='show running-config | include ip http server|secure|active',
        show_webauth_proxy='show running-config | include proxy http',
        show_webauth_param='show running-config | section parameter-map'
    ),
)
def rule_cve202520240(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20240 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the Web Authentication feature of Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to conduct a reflected cross-site scripting attack (XSS)
    on an affected device.
    
    The device is vulnerable if:
    1. Running a vulnerable version of IOS XE Software
    2. HTTP or HTTPS server is enabled
    3. Web Authentication feature is enabled
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (all versions prior to fixed releases)
    # Based on the advisory, this affects IOS XE Software when Web Auth is enabled
    # We'll check for common vulnerable version patterns
    vulnerable_version_patterns = [
        '16.', '17.1.', '17.2.', '17.3.', '17.4.', '17.5.', '17.6.', 
        '17.7.', '17.8.', '17.9.', '17.10.', '17.11.', '17.12.', '17.13.'
    ]

    # Check if the current device's software version matches vulnerable patterns
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if HTTP or HTTPS server is enabled
    http_config = commands.show_http_config
    http_enabled = 'ip http server' in http_config
    https_enabled = 'ip http secure-server' in http_config
    
    # Check if HTTP/HTTPS is disabled via active-session-modules
    http_disabled = 'ip http active-session-modules none' in http_config
    https_disabled = 'ip http secure-active-session-modules none' in http_config
    
    # Determine if HTTP/HTTPS is exploitable
    http_exploitable = http_enabled and not http_disabled
    https_exploitable = https_enabled and not https_disabled
    
    # If neither HTTP nor HTTPS is exploitable, device is not vulnerable
    if not (http_exploitable or https_exploitable):
        return

    # Check if Web Authentication is enabled (legacy mode)
    webauth_proxy = commands.show_webauth_proxy
    webauth_legacy_enabled = 'ip admission proxy http' in webauth_proxy

    # Check if Web Authentication is enabled (cEdge mode or wireless)
    webauth_param = commands.show_webauth_param
    webauth_param_enabled = 'parameter-map type webauth' in webauth_param

    # If Web Authentication is enabled, the device is vulnerable
    if webauth_legacy_enabled or webauth_param_enabled:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20240. "
            "The device is running a vulnerable version of IOS XE Software with HTTP/HTTPS server enabled "
            "and Web Authentication feature configured. This allows an unauthenticated, remote attacker to "
            "conduct a reflected cross-site scripting (XSS) attack. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-xss-VWyDgjOU"
        )
    else:
        # Web Authentication is not enabled, device is not vulnerable
        return