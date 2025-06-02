from comfy import high


@high(
    name='rule_cve202220848',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_wireless='show running-config | include ap|wireless'
    ),
)
def rule_cve202220848(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20848 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper processing of UDP datagrams in Embedded Wireless Controllers
    on Catalyst 9100 Series Access Points. An unauthenticated, remote attacker could exploit this
    vulnerability by sending malicious UDP datagrams to an affected device, causing it to reload
    and resulting in a denial of service (DoS) condition.
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
        f"Device {device.name} is vulnerable to CVE-2022-20848. "
        "The device is a Catalyst 9100 Series AP configured as an embedded wireless controller, "
        "which could allow an unauthenticated attacker to cause a denial of service through malicious UDP datagrams. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-udp-dos-XDyEwhNz"
    )
