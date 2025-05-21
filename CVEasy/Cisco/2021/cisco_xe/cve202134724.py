from comfy import high


@high(
    name='rule_cve202134724',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|username.*privilege 15|bootflash'
    ),
)
def rule_cve202134724(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34724 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability in the CLI could allow an authenticated, local attacker with high privileges
    to elevate privileges and execute arbitrary code as root by overwriting an installer file
    in the bootflash directory with arbitrary commands.
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
        f"Device {device.name} is potentially vulnerable to CVE-2021-34724. "
        "The device is running IOS XE SD-WAN Software with privileged users configured, "
        "which could allow an authenticated local attacker to elevate privileges and execute "
        "arbitrary code as root through bootflash file manipulation. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxesdwan-privesc-VP4FG3jD"
    )
