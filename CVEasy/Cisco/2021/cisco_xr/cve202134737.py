from comfy import high
import re


@high(
    name='rule_cve202134737',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_dhcp='show running-config | include ipv4 dhcp server'
    ),
)
def rule_cve202134737(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-34737 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to improper validation of DHCPv4 messages when processed by an affected device.
    An unauthenticated, remote attacker could exploit this vulnerability by sending malformed DHCPv4
    messages to an affected device, causing a NULL pointer dereference and resulting in a crash of the
    dhcpd process, leading to a denial of service condition.
    Note: Only the dhcpd process crashes and restarts automatically (takes about 2 minutes).
    """
    version_output = commands.show_version
    dhcp_output = commands.check_dhcp

    # Extract version string like '7.2.3'
    match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not match:
        return  # Could not determine version

    version = match.group(1)
    major, minor, patch = map(int, version.split("."))

    # Vulnerable if version < 7.3.2
    vulnerable = (
        (major < 7) or
        (major == 7 and (
            minor < 3 or
            (minor == 3 and patch < 2)
        ))
    )

    # Check if DHCPv4 server is enabled
    dhcp_server_enabled = 'ipv4 dhcp server' in dhcp_output

    if vulnerable and dhcp_server_enabled:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-34737. "
            f"Running IOS XR version {version} with DHCPv4 server enabled, which may allow "
            "an unauthenticated attacker to crash the dhcpd process via malformed DHCPv4 messages. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dhcp-dos-pjPVReLU"
        )
