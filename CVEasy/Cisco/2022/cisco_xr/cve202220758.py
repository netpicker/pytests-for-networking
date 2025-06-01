from comfy import high


@high(
    name='rule_cve202220758',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_bgp='show running-config | include router bgp|address-family l2vpn evpn'
    ),
)
def rule_cve202220758(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20758 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incorrect processing of BGP update messages containing specific EVPN attributes.
    An unauthenticated, remote attacker could exploit this vulnerability by sending crafted BGP update messages
    through an established trusted peer connection, causing the BGP process to restart and resulting in a
    denial of service (DoS) condition.
    """
    # Extract the output of the command to check BGP EVPN configuration
    bgp_output = commands.check_bgp

    # Check if BGP is configured with L2VPN EVPN address family
    bgp_configured = 'router bgp' in bgp_output
    evpn_configured = 'address-family l2vpn evpn' in bgp_output

    # Device is vulnerable if both BGP and L2VPN EVPN are configured
    is_vulnerable = bgp_configured and evpn_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20758. "
        "The device has BGP configured with L2VPN EVPN address-family, "
        "which could allow an unauthenticated attacker to cause a denial of service through crafted BGP update messages. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bgpevpn-zWTRtPBb"
    )
