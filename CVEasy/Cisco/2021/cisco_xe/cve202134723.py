from comfy import high


@high(
    name='rule_cve202134723',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|username.*privilege 15'
    ),
)
def rule_cve202134723(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34723 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability in a specific CLI command could allow an authenticated, local attacker
    with high privileges to overwrite arbitrary files in the configuration database due to
    insufficient validation of command parameters.
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
        f"Device {device.name} is potentially vulnerable to CVE-2021-34723. "
        "The device is running IOS XE SD-WAN Software with privileged users configured, "
        "which could allow an authenticated local attacker to overwrite arbitrary files "
        "in the configuration database through a specific CLI command. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxesdwan-arbfileov-MVOF3ZZn"
    )
