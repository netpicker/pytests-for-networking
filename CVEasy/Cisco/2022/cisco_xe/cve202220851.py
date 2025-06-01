from comfy import high


@high(
    name='rule_cve202220851',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_webui='show running-config | include ip http|restconf'
    ),
)
def rule_cve202220851(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20851 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient input validation in the web UI feature.
    An authenticated, remote attacker with Administrator privileges could exploit this
    vulnerability by sending crafted input to the web UI API, allowing them to execute
    arbitrary commands on the underlying operating system with root privileges.
    """
    # Extract the output of the command to check web UI configuration
    webui_output = commands.check_webui

    # Check if web UI or RESTCONF is enabled
    webui_enabled = any(feature in webui_output for feature in [
        'ip http server',
        'ip http secure-server',
        'restconf'
    ])

    # Assert that the device is not vulnerable
    assert not webui_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20851. "
        "The device has web UI or RESTCONF enabled, "
        "which could allow an authenticated attacker with Administrator privileges to execute arbitrary commands with root privileges. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-cmdinj-Gje47EMn"
    )
