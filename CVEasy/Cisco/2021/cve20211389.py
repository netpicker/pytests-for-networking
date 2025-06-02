from comfy import high
import re


@high(
    name='rule_cve20211389',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_ipv6_acl='show running-config | include ipv6 access-list|interface|ipv6 traffic-filter'
    ),
)
def rule_cve20211389(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1389 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to improper processing of IPv6 traffic that is sent through
    an affected device. An unauthenticated, remote attacker could exploit this vulnerability
    by sending crafted IPv6 packets that traverse the affected device, allowing them to bypass
    IPv6 access control lists (ACLs) configured on interfaces.
    """
    version_output = commands.show_version
    acl_output = commands.check_ipv6_acl

    # Extract version string like '6.6.2'
    match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not match:
        return  # Could not determine version

    version = match.group(1)
    major, minor, patch = map(int, version.split("."))

    current = (major, minor, patch)

    def is_vulnerable(v):
        return (
            (v[0] == 6 and v[1] == 6 and v[2] < 3) or
            (v[0] == 6 and v[1] == 7 and v[2] < 1) or
            (v[0] == 7 and v[1] == 1 and v[2] < 1) or
            (v[0] == 7 and v[1] == 2 and v[2] < 1)
        )

    vulnerable = is_vulnerable(current)

    # Check if IPv6 ACLs are configured and applied to interfaces
    has_ipv6_acl = 'ipv6 access-list' in acl_output
    acl_applied = 'ipv6 traffic-filter' in acl_output

    if vulnerable and has_ipv6_acl and acl_applied:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-1389. "
            f"Running IOS XR version {version} with IPv6 ACLs configured and applied to interfaces, "
            "which could allow an unauthenticated attacker to bypass ACL restrictions using crafted IPv6 packets. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv6-acl-CHgdYk8j"
        )
