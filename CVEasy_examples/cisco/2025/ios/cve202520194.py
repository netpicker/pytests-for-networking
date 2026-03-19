from comfy import high


@high(
    name='rule_cve202520194',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_http_config='show running-config | include ip http server|secure|active'
    ),
)
def rule_cve202520194(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20194 vulnerability in Cisco IOS XE Software.
    The vulnerability is in the web-based management interface and allows an authenticated, 
    low-privileged, remote attacker to perform an injection attack against an affected device.
    A successful exploit could allow the attacker to read limited files from the underlying 
    operating system or clear the syslog and licensing logs on the affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE (vulnerability only affects IOS XE, not IOS)
    if 'IOS XE' not in version_output:
        return

    # Extract HTTP server configuration
    http_config = commands.show_http_config

    # Check if HTTP server is enabled
    http_server_enabled = 'ip http server' in http_config
    https_server_enabled = 'ip http secure-server' in http_config

    # Check if the vulnerability is mitigated by active-session-modules none
    http_mitigated = 'ip http active-session-modules none' in http_config
    https_mitigated = 'ip http secure-active-session-modules none' in http_config

    # Determine if web-based management interface is exploitable
    http_exploitable = http_server_enabled and not http_mitigated
    https_exploitable = https_server_enabled and not https_mitigated

    # Device is vulnerable if either HTTP or HTTPS is exploitable
    is_vulnerable = http_exploitable or https_exploitable

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20194. "
        "The device is running Cisco IOS XE Software with the web-based management interface enabled, "
        "which makes it susceptible to command injection attacks that could allow an authenticated attacker "
        "to read limited files from the underlying operating system or clear the syslog and licensing logs. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-multi-ARNHM4v6"
    )