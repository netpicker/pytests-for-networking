from comfy import high


@high(
    name='rule_cve20211529',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|username.*privilege'
    ),
)
def rule_cve20211529(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1529 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability in the CLI could allow an authenticated, local attacker to execute
    arbitrary commands with root privileges due to insufficient input validation by the
    system CLI.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE SD-WAN software
    if 'IOS XE SD-WAN Software' not in version_output:
        return

    # Check for SD-WAN configuration and privileged users
    config = commands.check_sdwan

    # Check if SD-WAN is enabled
    sdwan_enabled = 'sdwan' in config

    # Check for users with any level of privileges
    has_users = 'username' in config

    # Device is vulnerable if running SD-WAN with any users configured
    is_vulnerable = sdwan_enabled and has_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1529. "
        "The device is running IOS XE SD-WAN Software with user accounts configured, "
        "which could allow an authenticated local attacker to execute arbitrary commands with root privileges. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-rhpbE34A"
    )
