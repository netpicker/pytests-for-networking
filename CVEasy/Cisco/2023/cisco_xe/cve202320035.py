from comfy import high


@high(
    name='rule_cve202320035',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan'
    ),
)
def rule_cve202320035(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20035 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability is due to insufficient input validation by the system CLI.
    An attacker with privileges to run commands could exploit this vulnerability by submitting
    crafted input to the system CLI, allowing them to execute commands with root-level privileges.
    """
    # Extract the output of the command to check SD-WAN configuration
    sdwan_output = commands.check_sdwan

    # Check if SD-WAN is configured
    sdwan_configured = 'sdwan' in sdwan_output

    # Assert that the device is not vulnerable
    assert not sdwan_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20035. "
        "The device has SD-WAN configured with CLI access, "
        "which could allow an attacker to execute arbitrary commands with root privileges. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-sdwan-VQAhEjYw"
    )
