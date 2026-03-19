from comfy import high


@high(
    name='rule_cve202520195',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include ip http server|secure|active'
    ),
)
def rule_cve202520195(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20195 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient CSRF protections for the web-based management interface,
    which allows an unauthenticated, remote attacker to perform a CSRF attack and execute commands
    on the CLI of an affected device by persuading an authenticated user to follow a crafted link.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE (vulnerability only affects IOS XE, not IOS)
    if 'IOS XE' not in version_output:
        return

    # Extract the configuration output
    config_output = commands.show_running_config

    # Check if HTTP server is enabled
    http_server_enabled = 'ip http server' in config_output

    # Check if HTTPS server is enabled
    https_server_enabled = 'ip http secure-server' in config_output

    # Check if HTTP is disabled via active-session-modules none
    http_disabled = 'ip http active-session-modules none' in config_output

    # Check if HTTPS is disabled via secure-active-session-modules none
    https_disabled = 'ip http secure-active-session-modules none' in config_output

    # Determine if the device is vulnerable
    # HTTP server is vulnerable if enabled and not disabled via active-session-modules
    http_vulnerable = http_server_enabled and not http_disabled

    # HTTPS server is vulnerable if enabled and not disabled via secure-active-session-modules
    https_vulnerable = https_server_enabled and not https_disabled

    # Device is vulnerable if either HTTP or HTTPS is vulnerable
    is_vulnerable = http_vulnerable or https_vulnerable

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20195. "
        "The device has the web-based management interface enabled without proper CSRF protections, "
        "which makes it susceptible to CSRF attacks that could allow an attacker to execute commands "
        "on the CLI by persuading an authenticated user to follow a crafted link. "
        "Disable the HTTP server using 'no ip http server' and 'no ip http secure-server' commands. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-multi-ARNHM4v6"
    )