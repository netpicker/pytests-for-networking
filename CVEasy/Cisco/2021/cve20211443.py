from comfy import high


@high(
    name='rule_cve20211443',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_webui='show running-config | include ip http|restconf|username.*privilege 15'
    ),
)
def rule_cve20211443(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1443 vulnerability in Cisco IOS XE Software web UI.
    The vulnerability allows an authenticated, remote attacker with high privileges to execute
    arbitrary code with root privileges on the underlying operating system due to improper
    sanitization of values parsed from configuration files.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for web UI configuration and privileged users
    config = commands.check_webui

    # Check if web UI is enabled
    webui_enabled = any(feature in config for feature in [
        'ip http server',
        'ip http secure-server',
        'restconf'
    ])

    # Check for users with high privileges (privilege level 15)
    has_privileged_users = 'privilege 15' in config

    # Device is vulnerable if web UI is enabled with privileged users
    is_vulnerable = webui_enabled and has_privileged_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1443. "
        "The device has web UI features enabled with privileged users configured, "
        "which could allow an authenticated remote attacker to execute arbitrary code with root privileges "
        "through configuration file tampering. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-os-cmd-inj-Ef6TV5e9"
    )
