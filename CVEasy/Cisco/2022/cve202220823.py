from comfy import high


@high(
    name='rule_cve202220823',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_ospfv3='show running-config | include router ospfv3|ipv6 router ospf'
    ),
)
def rule_cve202220823(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20823 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to incomplete input validation of specific OSPFv3 packets.
    An unauthenticated, remote attacker could exploit this vulnerability by sending a malicious
    OSPFv3 link-state advertisement (LSA) to an affected device, causing the OSPFv3 process to
    crash and restart multiple times, leading to a denial of service condition.
    Note: The OSPFv3 feature is disabled by default.
    """
    # Extract the output of the command to check OSPFv3 configuration
    ospfv3_output = commands.check_ospfv3

    # Check if OSPFv3 is enabled (either via 'router ospfv3' or 'ipv6 router ospf')
    ospfv3_enabled = any(feature in ospfv3_output for feature in [
        'router ospfv3',
        'ipv6 router ospf'
    ])

    # If OSPFv3 is not enabled, device is not vulnerable
    if not ospfv3_enabled:
        return

    # Assert that the device is not vulnerable
    assert not ospfv3_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20823. "
        "The device has OSPFv3 enabled, which could allow an unauthenticated attacker "
        "to cause a denial of service through malicious OSPFv3 LSA packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ospfv3-dos-48qutcu"
    )
