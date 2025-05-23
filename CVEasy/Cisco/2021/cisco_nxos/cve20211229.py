from comfy import high


@high(
    name='rule_cve20211229',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_ipv6='show running-config | include ipv6'
    ),
)
def rule_cve20211229(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1229 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to improper error handling when an IPv6-configured interface
    receives a specific type of ICMPv6 packet. An unauthenticated, remote attacker could
    exploit this vulnerability by sending a sustained rate of crafted ICMPv6 packets to a
    local IPv6 address, causing a memory leak in the ICMPv6 process that could lead to a
    denial of service condition.
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
        f"Device {device.name} is vulnerable to CVE-2021-1229. "
        "The device has IPv6 enabled, which could allow an unauthenticated attacker "
        "to cause a memory leak and denial of service through crafted ICMPv6 packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxos-nxos-icmpv6-dos-YD55jVCq"
    )
