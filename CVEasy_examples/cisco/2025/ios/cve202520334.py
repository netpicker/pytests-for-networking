from comfy import high


@high(
    name='rule_cve202520334',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include ip http server|secure|active'
    ),
)
def rule_cve202520334(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20334 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient input validation in the HTTP API subsystem, which allows
    a remote attacker to inject commands that will execute with root privileges into the underlying
    operating system.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE (vulnerability only affects IOS XE, not IOS)
    if 'IOS XE' not in version_output:
        return

    # Extract configuration output
    config_output = commands.show_running_config

    # Check if HTTP Server feature is enabled
    http_server_enabled = 'ip http server' in config_output
    https_server_enabled = 'ip http secure-server' in config_output

    # Check if the vulnerability is mitigated by configuration
    http_mitigated = 'ip http active-session-modules none' in config_output
    https_mitigated = 'ip http secure-active-session-modules none' in config_output

    # Determine if device is vulnerable
    # Device is vulnerable if:
    # - HTTP server is enabled without mitigation, OR
    # - HTTPS server is enabled without mitigation
    http_vulnerable = http_server_enabled and not http_mitigated
    https_vulnerable = https_server_enabled and not https_mitigated

    is_vulnerable = http_vulnerable or https_vulnerable

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20334. "
        "The device is running Cisco IOS XE Software with HTTP Server feature enabled, "
        "which makes it susceptible to command injection attacks that execute with root privileges. "
        "Disable the HTTP Server feature or apply the fixed software version. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-cmd-inject-rPJM8BGL"
    )