from comfy import high


@high(
    name='rule_cve202320231',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_webui='show running-config | include ip http|webui|lobby'
    ),
)
def rule_cve202320231(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20231 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient input validation in the web UI. An attacker could
    exploit this vulnerability by sending crafted input to the web UI using Lobby Ambassador credentials,
    allowing them to execute arbitrary Cisco IOS XE Software CLI commands with level 15 privileges.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (from CVE details)
    vulnerable_versions = [
        # 16.12 versions
        '16.12.4', '16.12.4a', '16.12.5', '16.12.5a', '16.12.5b', '16.12.6',
        '16.12.6a', '16.12.7', '16.12.8', '16.12.9',
        # 17.2-17.3 versions
        '17.2.2', '17.2.3', '17.3.1', '17.3.1a', '17.3.1w', '17.3.1x', '17.3.1z',
        '17.3.2', '17.3.2a', '17.3.3', '17.3.4', '17.3.4a', '17.3.4b', '17.3.4c',
        '17.3.5', '17.3.5a', '17.3.5b', '17.3.6',
        # 17.4-17.6 versions
        '17.4.1', '17.4.1a', '17.4.1b', '17.4.2', '17.4.2a',
        '17.5.1', '17.5.1a', '17.5.1b', '17.5.1c',
        '17.6.1', '17.6.1a', '17.6.1w', '17.6.1x', '17.6.1y', '17.6.1z', '17.6.1z1',
        '17.6.2', '17.6.3', '17.6.3a', '17.6.4', '17.6.5', '17.6.5a',
        # 17.7-17.10 versions
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.1a', '17.9.1w', '17.9.1x', '17.9.1x1', '17.9.1y', '17.9.2',
        '17.9.2a',
        '17.10.1', '17.10.1a', '17.10.1b'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check web UI and Lobby Ambassador configuration
    webui_output = commands.check_webui

    # Check if web UI and Lobby Ambassador are configured
    webui_enabled = any(service in webui_output for service in ['ip http', 'webui'])
    lobby_configured = 'lobby' in webui_output

    # Assert that the device is not vulnerable
    assert not (webui_enabled and lobby_configured), (
        f"Device {device.name} is vulnerable to CVE-2023-20231. "
        "The device is running a vulnerable version AND has web UI with Lobby Ambassador configured, "
        "which could allow an attacker to execute arbitrary commands with elevated privileges. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-cmdij-FzZAeXAy"
    )
