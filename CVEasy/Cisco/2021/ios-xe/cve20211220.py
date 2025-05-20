from comfy import high


@high(
    name='rule_cve20211220',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_webui='show running-config | include ip http|username'
    ),
)
def rule_cve20211220(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1220 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient error handling in the web UI.
    An authenticated, remote attacker with read-only privileges could exploit this vulnerability
    by sending crafted HTTP packets to an affected device, causing the web UI to become unresponsive
    and consume all available vty lines, resulting in a denial of service condition.
    """
    # Extract the output of the commands
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    webui_output = commands.check_webui

    # Check if web UI is enabled
    webui_enabled = 'ip http server' in webui_output or 'ip http secure-server' in webui_output

    # If web UI is not enabled, device is not vulnerable
    if not webui_enabled:
        return

    # Check if there are users with read-only privileges
    readonly_users = any(
        'username' in line and 'privilege 1' in line
        for line in webui_output.splitlines()
    )

    # Device is vulnerable if web UI is enabled and read-only users exist
    is_vulnerable = webui_enabled and readonly_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1220. "
        "The device has web UI enabled with read-only users configured, which could allow an authenticated attacker "
        "to cause a denial of service through crafted HTTP packets. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xe-webui-dos-z9yqYQAn"
    )
