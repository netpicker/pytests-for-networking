from comfy import high


@high(
    name='rule_cve202220694',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_rpki='show running-config | include router bgp|rpki'
    ),
)
def rule_cve202220694(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20694 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to incorrect handling of RPKI to Router (RTR) Protocol packet headers
    in the Resource Public Key Infrastructure (RPKI) feature. An unauthenticated, remote attacker
    could exploit this vulnerability by sending crafted RTR packets to cause the BGP process to crash,
    resulting in a denial of service (DoS) condition.
    """
    # Extract the output of the command to check BGP and RPKI configuration
    rpki_output = commands.check_rpki

    # Check if BGP is configured with RPKI
    bgp_configured = 'router bgp' in rpki_output
    rpki_configured = 'rpki' in rpki_output

    # Device is vulnerable if both BGP and RPKI are configured
    is_vulnerable = bgp_configured and rpki_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20694. "
        "The device has BGP configured with RPKI, "
        "which could allow an unauthenticated attacker to cause a denial of service through crafted RTR packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-rpki-dos-2EgCNeKE"
    )
