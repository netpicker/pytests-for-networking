from comfy import high
import re


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
    version_output = commands.show_version
    ipv6_output = commands.check_ipv6

    # Extract version string like '6.7.2' or '7.1.1' from 'show version' output
    match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not match:
        return  # Could not determine version

    version = match.group(1)
    major, minor, patch = map(int, version.split("."))

    # Affected if version < 6.7.3 or < 7.1.2
    vulnerable = (
        (major == 6 and (minor < 7 or (minor == 7 and patch < 3))) or
        (major == 7 and (minor == 1 and patch < 2))
    )

    # Check if IPv6 is configured on management interfaces
    has_mgmt_ipv6 = 'ipv6' in ipv6_output and 'management-interface' in ipv6_output

    # If both conditions are true, the device is vulnerable
    if vulnerable and has_mgmt_ipv6:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-1268. "
            f"Running IOS XR version {version} with IPv6 enabled on management interfaces, which may allow "
            "an adjacent attacker to cause a denial of service through IPv6 flooding using node-local "
            "multicast packets. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xripv6-spJem78K"
        )
