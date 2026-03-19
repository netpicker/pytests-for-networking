from comfy import high


@high(
    name='rule_cve202520193',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include ip http server|secure|active'
    ),
)
def rule_cve202520193(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20193 vulnerability in Cisco IOS XE Software.
    The vulnerability is in the web-based management interface and allows an authenticated, 
    low-privileged, remote attacker to perform an injection attack and read files from the 
    underlying operating system due to insufficient input validation.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE (vulnerability only affects IOS XE, not IOS)
    if 'IOS XE' not in version_output:
        return

    # Extract configuration output
    config_output = commands.show_running_config

    # Check if HTTP server is enabled (must not be preceded by 'no ')
    http_server_enabled = 'ip http server' in config_output and 'no ip http server' not in config_output
    https_server_enabled = 'ip http secure-server' in config_output and 'no ip http secure-server' not in config_output

    # Check if the vulnerability is mitigated by active-session-modules none
    http_mitigated = 'ip http active-session-modules none' in config_output
    https_mitigated = 'ip http secure-active-session-modules none' in config_output

    # Determine if web-based management interface is exploitable
    http_exploitable = http_server_enabled and not http_mitigated
    https_exploitable = https_server_enabled and not https_mitigated

    # Device is vulnerable if either HTTP or HTTPS is exploitable
    is_vulnerable = http_exploitable or https_exploitable

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20193. "
        "The device is running Cisco IOS XE Software with the web-based management interface enabled, "
        "which allows an authenticated, low-privileged attacker to read files from the underlying operating system. "
        "Disable the HTTP server using 'no ip http server' and 'no ip http secure-server' commands, "
        "or apply the appropriate software update. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-multi-ARNHM4v6"
    )