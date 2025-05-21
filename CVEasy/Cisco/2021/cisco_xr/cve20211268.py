from comfy import high


@high(
    name='rule_cve20211268',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_ipv6='show running-config | include ipv6|management-interface'
    ),
)
def rule_cve20211268(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1268 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incorrect forwarding of IPv6 packets with node-local multicast
    group address destinations received on management interfaces. An unauthenticated, adjacent
    attacker could exploit this vulnerability by connecting to the same network as the management
    interfaces and injecting IPv6 packets with node-local multicast group address destinations,
    causing an IPv6 flood and potential DoS condition.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    ipv6_output = commands.check_ipv6

    # Check if IPv6 is enabled on management interfaces
    has_mgmt_ipv6 = 'ipv6' in ipv6_output and 'management-interface' in ipv6_output

    # If IPv6 is not enabled on management interfaces, device is not vulnerable
    if not has_mgmt_ipv6:
        return

    # Assert that the device is not vulnerable
    assert not has_mgmt_ipv6, (
        f"Device {device.name} is vulnerable to CVE-2021-1268. "
        "The device has IPv6 enabled on management interfaces, which could allow an adjacent attacker "
        "to cause a denial of service through IPv6 flooding with node-local multicast packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xripv6-spJem78K"
    )
