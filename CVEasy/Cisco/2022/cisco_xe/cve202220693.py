from comfy import high


@high(
    name='rule_cve202220693',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_webui='show running-config | include ip http|restconf'
    ),
)
def rule_cve202220693(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20693 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient input validation in the web UI feature.
    An authenticated, remote attacker could exploit this vulnerability by sending crafted input
    to the web UI API, allowing them to inject commands to the underlying operating system with
    root privileges.
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
        f"Device {device.name} is vulnerable to CVE-2022-20693. "
        "The device has web UI or RESTCONF enabled, "
        "which could allow an authenticated attacker to inject commands with root privileges through crafted API input. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webuiapi-inj-Nyrq92Od"
    )
