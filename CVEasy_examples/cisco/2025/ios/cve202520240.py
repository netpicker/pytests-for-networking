from comfy import high


@high(
    name='rule_cve202520240',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_http_config='show running-config | include ip http server|secure|active',
        show_webauth_switch='show running-config | include proxy http',
        show_webauth_cedge='show running-config | section parameter-map',
    ),
)
def rule_cve202520240(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20240 vulnerability in Cisco IOS XE Software.
    The vulnerability is in the Web Authentication feature and allows an unauthenticated, remote attacker
    to conduct a reflected cross-site scripting (XSS) attack. This is due to improper sanitization of
    user-supplied input.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE (vulnerability only affects IOS XE, not IOS)
    if 'IOS XE' not in version_output:
        return

    # Check if HTTP or HTTPS server is enabled
    http_config = commands.show_http_config
    
    http_enabled = 'ip http server' in http_config
    https_enabled = 'ip http secure-server' in http_config
    
    # Check if HTTP/HTTPS is disabled via active-session-modules none
    http_disabled = 'ip http active-session-modules none' in http_config
    https_disabled = 'ip http secure-active-session-modules none' in http_config
    
    # Determine if HTTP server is exploitable
    http_exploitable = http_enabled and not http_disabled
    https_exploitable = https_enabled and not https_disabled
    
    # If neither HTTP nor HTTPS is exploitable, device is not vulnerable
    if not (http_exploitable or https_exploitable):
        return

    # Check if Web Authentication is enabled (legacy mode for switches)
    webauth_switch_config = commands.show_webauth_switch
    webauth_legacy_enabled = 'ip admission' in webauth_switch_config and 'proxy http' in webauth_switch_config

    # Check if Web Authentication is enabled (cEdge mode or wireless)
    webauth_cedge_config = commands.show_webauth_cedge
    webauth_cedge_enabled = 'parameter-map type webauth' in webauth_cedge_config

    # Device is vulnerable if Web Authentication is enabled
    is_vulnerable = webauth_legacy_enabled or webauth_cedge_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20240. "
        "The device is running Cisco IOS XE Software with HTTP/HTTPS enabled AND Web Authentication feature enabled, "
        "which makes it susceptible to reflected cross-site scripting (XSS) attacks. "
        "An attacker could exploit this to steal user cookies from the affected device. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-xss-VWyDgjOU"
    )