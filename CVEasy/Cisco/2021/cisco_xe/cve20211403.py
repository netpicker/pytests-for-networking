from comfy import high


@high(
    name='rule_cve20211403',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_webui='show running-config | include ip http|restconf|websocket'
    ),
)
def rule_cve20211403(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1403 vulnerability in Cisco IOS XE Software web UI.
    The vulnerability allows an unauthenticated, remote attacker to conduct a cross-site
    WebSocket hijacking (CSWSH) attack and cause a denial of service (DoS) condition by
    corrupting memory on the affected device through crafted links.
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
        f"Device {device.name} is potentially vulnerable to CVE-2021-1403. "
        "The device has web UI features enabled, which could allow an unauthenticated remote attacker "
        "to conduct a cross-site WebSocket hijacking attack and cause a denial of service condition. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-cswsh-FKk9AzT5"
    )
