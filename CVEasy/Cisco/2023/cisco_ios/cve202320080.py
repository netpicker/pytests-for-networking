from comfy import high


@high(
    name='rule_cve202320080',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_dhcpv6='show running-config | include ipv6 dhcp'
    ),
)
def rule_cve202320080(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20080 vulnerability in Cisco IOS Software.
    The vulnerability is due to insufficient validation of data boundaries in the IPv6 DHCP (DHCPv6)
    relay and server features. An attacker could exploit this vulnerability by sending crafted DHCPv6
    messages to an affected device, causing it to reload unexpectedly.
    """
    # Extract the output of the command to check DHCPv6 configuration
    dhcpv6_output = commands.check_dhcpv6

    # Check if DHCPv6 relay or server is configured
    dhcpv6_configured = any(feature in dhcpv6_output for feature in ['ipv6 dhcp relay', 'ipv6 dhcp server'])

    # Assert that the device is not vulnerable
    assert not dhcpv6_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20080. "
        "The device has IPv6 DHCP relay or server configured, "
        "which could allow an attacker to cause a denial of service through crafted DHCPv6 messages. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-dhcpv6-dos-44cMvdDK"
    )
