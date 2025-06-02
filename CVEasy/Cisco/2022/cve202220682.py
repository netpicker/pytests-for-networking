from comfy import high


@high(
    name='rule_cve202220682',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_wireless='show running-config | include wireless|capwap'
    ),
)
def rule_cve202220682(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20682 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to inadequate input validation of incoming CAPWAP packets encapsulating
    multicast DNS (mDNS) queries in the Catalyst 9000 Family Wireless Controllers. An attacker could
    exploit this vulnerability by connecting to a wireless network and sending a crafted mDNS query,
    which would flow through and be processed by the wireless controller.
    """
    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a Catalyst 9000 Series
    is_cat9k = 'C9' in platform_output

    # If not a Catalyst 9000 device, it's not vulnerable
    if not is_cat9k:
        return

    # Extract the output of the command to check wireless/CAPWAP configuration
    wireless_output = commands.check_wireless

    # Check if wireless controller and CAPWAP are configured
    wireless_configured = any(feature in wireless_output for feature in ['wireless', 'capwap'])

    # Device is vulnerable if it's a Cat9K and has wireless/CAPWAP configured
    is_vulnerable = is_cat9k and wireless_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20682. "
        "The device is a Catalyst 9000 Series wireless controller with CAPWAP configured, "
        "which could allow an unauthenticated attacker to cause a denial of service through crafted mDNS queries. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c9800-capwap-mdns-6PSn7gKU"
    )
