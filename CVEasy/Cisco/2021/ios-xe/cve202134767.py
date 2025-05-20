from comfy import high


@high(
    name='rule_cve202134767',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_ipv6='show running-config | include ipv6'
    ),
)
def rule_cve202134767(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34767 vulnerability in Cisco IOS XE Wireless Controller Software.
    The vulnerability in IPv6 traffic processing could allow an unauthenticated, adjacent attacker
    to cause a Layer 2 (L2) loop in a configured VLAN, resulting in a denial of service (DoS)
    condition due to a logic error when processing specific link-local IPv6 traffic.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a Catalyst 9800 Series Wireless Controller
    platform_output = commands.check_platform
    vulnerable_platforms = [
        'C9800', 'Catalyst 9800'
    ]
    is_wireless_controller = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_wireless_controller:
        return

    # Check for IPv6 configuration
    ipv6_config = commands.check_ipv6

    # Check if IPv6 is enabled
    ipv6_enabled = 'ipv6' in ipv6_config

    # Device is vulnerable if IPv6 is enabled on a Catalyst 9800 Wireless Controller
    is_vulnerable = ipv6_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-34767. "
        "The device is a Catalyst 9800 Series Wireless Controller with IPv6 enabled, which could allow "
        "an unauthenticated adjacent attacker to cause a Layer 2 loop and denial of service condition "
        "through crafted IPv6 packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-ipv6-dos-NMYeCnZv"
    )
