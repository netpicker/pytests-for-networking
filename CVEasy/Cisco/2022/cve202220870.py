from comfy import high


@high(
    name='rule_cve202220870',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_mpls='show running-config | include mpls'
    ),
)
def rule_cve202220870(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20870 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient input validation of IPv4 traffic in the egress MPLS
    packet processing function of Catalyst 3650, 3850, and 9000 Family Switches. An unauthenticated,
    remote attacker could exploit this vulnerability by sending a malformed packet out of an affected
    MPLS-enabled interface, causing the device to reload.
    """
    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a vulnerable Catalyst model (3650, 3850, or 9000 series)
    is_vulnerable_platform = any(model in platform_output for model in ['C3650', 'C3850', 'C9'])

    # If not a vulnerable Catalyst model, it's not vulnerable
    if not is_vulnerable_platform:
        return

    # Extract the output of the command to check MPLS configuration
    mpls_output = commands.check_mpls

    # Check if MPLS is enabled
    mpls_enabled = 'mpls' in mpls_output

    # Device is vulnerable if it's a vulnerable platform and has MPLS enabled
    is_vulnerable = is_vulnerable_platform and mpls_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20870. "
        "The device is a Catalyst 3650/3850/9000 switch with MPLS enabled, "
        "which could allow an unauthenticated attacker to cause a denial of service through malformed packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-mpls-dos-Ab4OUL3"
    )
