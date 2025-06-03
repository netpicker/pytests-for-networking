from comfy import high


@high(
    name='rule_cve202220847',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_dhcp='show running-config | include ip dhcp|wireless'
    ),
)
def rule_cve202220847(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20847 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper processing of DHCP messages in Catalyst 9000 Family
    Wireless Controllers. An unauthenticated, remote attacker could exploit this vulnerability
    by sending malicious DHCP messages to an affected device, causing it to reload and resulting
    in a denial of service (DoS) condition.
    """
    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a Catalyst 9000 Series
    is_cat9k = 'C9' in platform_output

    # If not a Catalyst 9000 device, it's not vulnerable
    if not is_cat9k:
        return

    # Extract the output of the command to check DHCP and wireless configuration
    dhcp_output = commands.check_dhcp

    # Check if DHCP and wireless are configured
    dhcp_configured = 'ip dhcp' in dhcp_output
    wireless_configured = 'wireless' in dhcp_output

    # Device is vulnerable if it's a Cat9K and has both DHCP and wireless configured
    is_vulnerable = is_cat9k and dhcp_configured and wireless_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20847. "
        "The device is a Catalyst 9000 Series wireless controller with DHCP configured, "
        "which could allow an unauthenticated attacker to cause a denial of service through malicious DHCP messages. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-dhcp-dos-76pCjPxK"
    )
