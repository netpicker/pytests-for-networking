from comfy import high


@high(
    name='rule_cve202220684',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_wireless='show running-config | include wireless|snmp-server'
    ),
)
def rule_cve202220684(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20684 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to a lack of input validation of the information used to generate an SNMP trap
    related to a wireless client connection event in Catalyst 9000 Family Wireless Controllers. An attacker
    could exploit this vulnerability by sending an 802.1x packet with crafted parameters during the wireless
    authentication setup phase of a connection.
    """
    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a Catalyst 9000 Series
    is_cat9k = 'C9' in platform_output

    # If not a Catalyst 9000 device, it's not vulnerable
    if not is_cat9k:
        return

    # Extract the output of the command to check wireless and SNMP configuration
    wireless_output = commands.check_wireless

    # Check if wireless controller and SNMP traps are configured
    wireless_configured = 'wireless' in wireless_output
    snmp_configured = 'snmp-server' in wireless_output

    # Device is vulnerable if it's a Cat9K and has both wireless and SNMP configured
    is_vulnerable = is_cat9k and wireless_configured and snmp_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20684. "
        "The device is a Catalyst 9000 Series wireless controller with SNMP traps configured, "
        "which could allow an unauthenticated attacker to cause a denial of service through crafted 802.1x packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c9800-snmp-trap-dos-mjent3Ey"
    )
