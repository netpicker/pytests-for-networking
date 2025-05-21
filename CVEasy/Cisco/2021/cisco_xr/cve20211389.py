from comfy import high


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
    # Extract the output of the commands
    version_output = commands.show_version
    acl_output = commands.check_ipv6_acl

    # Check if IPv6 ACLs are configured and applied to interfaces
    has_ipv6_acl = 'ipv6 access-list' in acl_output
    acl_applied = 'ipv6 traffic-filter' in acl_output

    # If no IPv6 ACLs are configured or applied, device is not vulnerable
    if not (has_ipv6_acl and acl_applied):
        return

    # Assert that the device is not vulnerable
    assert not (has_ipv6_acl and acl_applied), (
        f"Device {device.name} is vulnerable to CVE-2021-1389. "
        "The device has IPv6 ACLs configured and applied to interfaces, which could allow "
        "an unauthenticated attacker to bypass ACL restrictions through crafted IPv6 packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv6-acl-CHgdYk8j""
    )
