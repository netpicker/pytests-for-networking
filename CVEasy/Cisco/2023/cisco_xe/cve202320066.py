from comfy import high


@high(
    name='rule_cve202320066',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_webui='show running-config | include ip http|webui'
    ),
)
def rule_cve202320066(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20066 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient security configuration in the web UI.
    An attacker could exploit this vulnerability by sending a crafted request to the web UI,
    allowing them to gain read access to files outside the filesystem mountpoint.
    """
    # Extract the output of the command to check web UI configuration
    webui_output = commands.check_webui

    # Check if web UI is enabled
    webui_enabled = any(service in webui_output for service in ['ip http', 'webui'])

    # Assert that the device is not vulnerable
    assert not webui_enabled, (
        f"Device {device.name} is vulnerable to CVE-2023-20066. "
        "The device has web UI enabled, which could allow an attacker to access files "
        "outside the filesystem mountpoint through path traversal. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-pthtrv-es7GSb9V"
    )
