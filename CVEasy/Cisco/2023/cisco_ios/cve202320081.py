from comfy import high


@high(
    name='rule_cve202320081',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_dhcpv6_client='show running-config | include ipv6 dhcp client'
    ),
)
def rule_cve202320081(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20081 vulnerability in Cisco IOS Software.
    The vulnerability is due to insufficient validation of DHCPv6 messages in the DHCPv6 client module.
    An attacker could exploit this vulnerability by sending crafted DHCPv6 messages to an affected device,
    causing it to reload and resulting in a denial of service (DoS) condition.
    Note: To successfully exploit this vulnerability, the attacker would need to either control the DHCPv6
    server or be in a man-in-the-middle position.
    """
    # Extract the output of the command to check DHCPv6 client configuration
    dhcpv6_output = commands.check_dhcpv6_client

    # Check if DHCPv6 client is configured
    dhcpv6_client_configured = 'ipv6 dhcp client' in dhcpv6_output

    # Assert that the device is not vulnerable
    assert not dhcpv6_client_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20081. "
        "The device has DHCPv6 client configured, "
        "which could allow an attacker to cause a denial of service through crafted DHCPv6 messages. "
        "For more information,see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftdios-dhcpv6-cli-Zf3zTv"
    )
