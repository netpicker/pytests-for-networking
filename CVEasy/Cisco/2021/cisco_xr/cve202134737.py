
from comfy import high


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
    # Extract the output of the commands
    version_output = commands.show_version
    dhcp_output = commands.check_dhcp

    # Check if DHCPv4 server is enabled
    dhcp_server_enabled = 'ipv4 dhcp server' in dhcp_output

    # If DHCPv4 server is not enabled, device is not vulnerable
    if not dhcp_server_enabled:
        return

    # Assert that the device is not vulnerable
    assert not dhcp_server_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-34737. "
        "The device has DHCPv4 server enabled, which could allow an unauthenticated attacker "
        "to cause a denial of service through malformed DHCPv4 messages. "
        ""For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dhcp-dos-pjPVReLU""
    )
