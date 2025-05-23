
from comfy import high


@high(
    name='rule_cve20211387',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_ipv6='show running-config | include ipv6'
    ),
)
def rule_cve20211387(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1387 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to improper resource management when processing certain IPv6 packets.
    An unauthenticated, remote attacker could exploit this vulnerability by sending multiple crafted
    IPv6 packets to an affected device, causing the network stack to run out of available buffers
    and resulting in a denial of service condition.
    """
    # Extract the output of the command to check IPv6 configuration
    ipv6_output = commands.check_ipv6

    # Check if IPv6 is configured on any interface
    ipv6_enabled = any(feature in ipv6_output for feature in [
        'ipv6 address',
        'ipv6 enable'
    ])

    # If IPv6 is not enabled, device is not vulnerable
    if not ipv6_enabled:
        return

    # Assert that the device is not vulnerable
    assert not ipv6_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-1387. "
        "The device has IPv6 enabled, which could allow an unauthenticated attacker "
        "to cause a denial of service through crafted IPv6 packets that exhaust network stack buffers. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ipv6-netstack-edXPGV7K"
    )
