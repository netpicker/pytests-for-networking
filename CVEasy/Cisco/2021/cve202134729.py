from comfy import high


@high(
    name='rule_cve202134729',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|username.*privilege 15'
    ),
)
def rule_cve202134729(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34729 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability in the CLI could allow an authenticated, local attacker with high privileges
    to execute arbitrary commands with elevated privileges on an affected device due to
    insufficient validation of arguments passed to certain CLI commands.
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

    # Check for users with high privileges (privilege level 15)
    has_privileged_users = 'privilege 15' in config

    # Device is vulnerable if running SD-WAN with privileged users
    is_vulnerable = sdwan_enabled and has_privileged_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-34729. "
        "The device is running IOS XE SD-WAN Software with privileged users configured, "
        "which could allow an authenticated local attacker to execute arbitrary commands "
        "with elevated privileges through command injection in the CLI. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ioxesdwan-clicmdinj-7bYX5k3"
    )
