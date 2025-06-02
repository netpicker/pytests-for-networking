from comfy import high


@high(
    name='rule_cve202220915',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_6vpe='show running-config | include vrf|ipv6|zone',
        check_zbfw='show running-config | include zone-pair|class-map|policy-map'
    ),
)
def rule_cve202220915(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20915 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper error handling of an IPv6 packet that is forwarded from
    an MPLS and ZBFW-enabled interface in a 6VPE deployment. An unauthenticated, adjacent attacker
    could exploit this vulnerability by sending a crafted IPv6 packet sourced from a device on the
    IPv6-enabled VRF interface through the affected device.
    """
    # Extract the output of the commands
    vpe_output = commands.check_6vpe
    zbfw_output = commands.check_zbfw

    # Check if 6VPE is configured (requires VRF and IPv6)
    vrf_configured = 'vrf' in vpe_output
    ipv6_configured = 'ipv6' in vpe_output
    vpe_configured = vrf_configured and ipv6_configured

    # Check if Zone-Based Firewall is configured
    zbfw_configured = any(feature in zbfw_output for feature in [
        'zone-pair',
        'class-map',
        'policy-map'
    ])

    # Device is vulnerable if both 6VPE and ZBFW are configured
    is_vulnerable = vpe_configured and zbfw_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20915. "
        "The device has IPv6 VPN over MPLS (6VPE) and Zone-Based Firewall configured, "
        "which could allow an adjacent attacker to cause a denial of service through crafted IPv6 packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-6vpe-dos-tJBtf5Zv"
    )
