from comfy import high


@high(
    name='rule_cve20211435',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_webui='show running-config | include ip http|restconf'
    ),
)
def rule_cve20211435(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1435 vulnerability in Cisco IOS XE Software web UI.
    The vulnerability allows an authenticated, remote attacker to inject arbitrary commands
    that can be executed as the root user due to insufficient input validation in the web UI.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for web UI configuration
    webui_config = commands.check_webui
    webui_enabled = any(feature in webui_config for feature in [
        'ip http server',
        'ip http secure-server',
        'restconf'
    ])

    # If web UI is enabled, device is potentially vulnerable
    assert not webui_enabled, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1435. "
        "The device has web UI features enabled, which could allow an authenticated remote attacker "
        "to inject arbitrary commands that can be executed as the root user. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webcmdinjsh-UFJxTgZD"
    )
