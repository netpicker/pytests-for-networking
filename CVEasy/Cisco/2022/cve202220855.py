from comfy import high


@high(
    name='rule_cve202220855',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_wireless='show running-config | include ap|wireless'
    ),
)
def rule_cve202220855(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20855 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper checks throughout the restart of certain system processes
    in Embedded Wireless Controllers on Catalyst Access Points. An authenticated, local attacker with
    privilege level 15 could exploit this vulnerability by executing certain CLI commands to escape
    the restricted controller shell and execute arbitrary commands on the underlying OS as root.
    """
    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a Catalyst 9100 Series AP
    is_cat9100 = 'C91' in platform_output

    # If not a Catalyst 9100 device, it's not vulnerable
    if not is_cat9100:
        return

    # Extract the output of the command to check wireless configuration
    wireless_output = commands.check_wireless

    # Check if device is configured as an embedded wireless controller
    wireless_controller_enabled = any(feature in wireless_output for feature in [
        'ap sso',
        'wireless management interface',
        'wireless controller'
    ])

    # Device is vulnerable if it's a Cat9100 and configured as wireless controller
    is_vulnerable = is_cat9100 and wireless_controller_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20855. "
        "The device is a Catalyst 9100 Series AP configured as an embedded wireless controller, "
        "which could allow a privileged attacker to execute arbitrary commands as root. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewc-priv-esc-nderYLtK"
    )
