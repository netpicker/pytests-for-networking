from comfy import high


@high(
    name='rule_cve20211374',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_webui='show running-config | include ip http|restconf|username'
    ),
)
def rule_cve20211374(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1374 vulnerability in Cisco IOS XE Wireless Controller Software.
    The vulnerability allows an authenticated, remote attacker with high privileges to conduct a
    stored cross-site scripting (XSS) attack against other users of the web-based management interface.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software and is a Catalyst 9000
    if 'IOS XE Software' not in version_output or 'C9' not in version_output:
        return

    # Check for web UI configuration and privileged users
    webui_config = commands.check_webui
    # Check if web UI is enabled
    webui_enabled = any(feature in webui_config for feature in [
        'ip http server',
        'ip http secure-server',
        'restconf'
    ])

    # Check for users with high privileges (15)
    has_privileged_users = 'privilege 15' in webui_config

    # Device is vulnerable if web UI is enabled and has privileged users
    is_vulnerable = webui_enabled and has_privileged_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1374. "
        "The device is a Catalyst 9000 with web UI features enabled and privileged users configured, "
        "which could allow an authenticated attacker to conduct stored XSS attacks. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-xss-cAfMtCzv"
    )
