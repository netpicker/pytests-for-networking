
from comfy import high


@high(
    name='rule_cve20211440',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_rpki='show running-config | include router bgp|rpki'
    ),
)
def rule_cve20211440(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1440 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incorrect handling of specific RPKI to Router (RTR) Protocol
    packet headers. An unauthenticated, remote attacker could exploit this vulnerability by
    compromising the RPKI validator server or using man-in-the-middle techniques to send crafted
    RTR packets, causing the BGP process to crash and resulting in a denial of service condition.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    rpki_output = commands.check_rpki

    # Check if BGP is configured with RPKI
    has_bgp = 'router bgp' in rpki_output
    has_rpki = 'rpki' in rpki_output

    # If BGP is not configured or RPKI is not enabled, device is not vulnerable
    if not (has_bgp and has_rpki):
        return

    # Assert that the device is not vulnerable
    assert not (has_bgp and has_rpki), (
        f"Device {device.name} is vulnerable to CVE-2021-1440. "
        "The device has BGP configured with RPKI enabled, which could allow an unauthenticated attacker "
        "to cause a denial of service through crafted RTR packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xrbgp-rpki-dos-gvmjqxbk""
    )
