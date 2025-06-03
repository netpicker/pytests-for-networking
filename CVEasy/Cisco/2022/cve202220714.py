from comfy import high


@high(
    name='rule_cve202220714',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_linecard='show inventory | include Lightspeed-Plus'
    ),
)
def rule_cve202220714(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20714 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incorrect handling of malformed packets in the data plane microcode
    of Lightspeed-Plus line cards for ASR 9000 Series routers. An unauthenticated, remote attacker
    could exploit this vulnerability by sending crafted IPv4 or IPv6 packets through an affected device,
    causing the line card to reset and resulting in a denial of service condition.
    """
    # Extract the output of the command to check for Lightspeed-Plus line cards
    linecard_output = commands.check_linecard

    # Check if Lightspeed-Plus line cards are present
    lightspeed_plus_present = 'Lightspeed-Plus' in linecard_output

    # Assert that the device is not vulnerable
    assert not lightspeed_plus_present, (
        f"Device {device.name} is vulnerable to CVE-2022-20714. "
        "The device has Lightspeed-Plus line cards installed, "
        "which could allow an unauthenticated attacker to cause a denial of service through crafted IPv4/IPv6 packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lsplus-Z6AQEOjk"
    )
