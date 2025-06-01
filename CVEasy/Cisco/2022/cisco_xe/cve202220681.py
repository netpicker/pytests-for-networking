from comfy import high


@high(
    name='rule_cve202220681',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis'
    ),
)
def rule_cve202220681(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20681 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient validation of user privileges after executing certain CLI commands
    on Cisco Catalyst 9000 Family Switches and Wireless Controllers. An authenticated, local attacker with low
    privileges could exploit this vulnerability by executing certain CLI commands to elevate their privileges
    to level 15.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a Catalyst 9000 Series
    is_cat9k = 'C9' in platform_output

    # If not a Catalyst 9000 device, it's not vulnerable
    if not is_cat9k:
        return

    # Assert that the device is not vulnerable
    assert not is_cat9k, (
        f"Device {device.name} is vulnerable to CVE-2022-20681. "
        "The device is a Catalyst 9000 Series switch/wireless controller, "
        "which could allow an authenticated attacker to elevate privileges to level 15 through certain CLI commands. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-priv-esc-ybvHKO5"
    )
