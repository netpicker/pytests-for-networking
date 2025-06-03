from comfy import high


@high(
    name='rule_cve202320072',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_tunnel='show running-config | include tunnel|gre'
    ),
)
def rule_cve202320072(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20072 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper handling of large fragmented tunnel protocol packets.
    An attacker could exploit this vulnerability by sending crafted fragmented packets to an affected system,
    causing it to reload and resulting in a denial of service (DoS) condition.
    """
    # Extract the output of the command to check tunnel configuration
    tunnel_output = commands.check_tunnel

    # Check if any tunnel protocols (like GRE) are configured
    tunnel_configured = any(protocol in tunnel_output for protocol in ['tunnel', 'gre'])

    # Assert that the device is not vulnerable
    assert not tunnel_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20072. "
        "The device has tunnel protocols configured (e.g., GRE), "
        "which could allow an attacker to cause a denial of service through crafted fragmented packets. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-gre-crash-p6nE5Sq5"
    )
