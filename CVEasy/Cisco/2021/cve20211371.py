from comfy import high


@high(
    name='rule_cve20211371',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|line console|aaa|authorization'
    ),
)
def rule_cve20211371(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1371 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability allows an authenticated, local attacker with read-only privileges to
    obtain administrative privileges by using the console port when the device is in the
    default SD-WAN configuration.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE SD-WAN software
    if 'IOS XE SD-WAN Software' not in version_output:
        return

    # Check for SD-WAN and console configuration
    config = commands.check_sdwan

    # Check if SD-WAN is enabled
    sdwan_enabled = 'sdwan' in config

    # Check if console has default authentication/authorization
    has_default_console = (
        'line console 0' in config and
        'aaa authorization console' not in config and
        'authorization exec' not in config
    )

    # Device is vulnerable if running SD-WAN with default console config
    is_vulnerable = sdwan_enabled and has_default_console

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1371. "
        "The device is running IOS XE SD-WAN Software with default console configuration, "
        "which could allow an authenticated local attacker with read-only privileges to "
        "obtain administrative privileges through the console port. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-esc-rSNVvTf9"
    )
