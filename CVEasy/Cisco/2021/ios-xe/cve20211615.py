from comfy import high


@high(
    name='rule_cve20211615',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_wireless='show running-config | include ap role active|ap capwap'
    ),
)
def rule_cve20211615(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1615 vulnerability in Cisco IOS XE Software's Embedded
    Wireless Controller (EWC) for Catalyst Access Points. The vulnerability in the packet
    processing functionality could allow an unauthenticated, remote attacker to cause a
    denial of service (DoS) condition due to insufficient buffer allocation.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a vulnerable platform (Catalyst 9100/9100L Series APs)
    platform_output = commands.check_platform
    vulnerable_platforms = [
        'C9115', 'C9117', 'C9120',
        'C9130', 'C9105', 'C9124'
    ]
    is_vulnerable_platform = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_vulnerable_platform:
        return

    # Check for EWC configuration
    wireless_config = commands.check_wireless

    # Check if device is configured as an active EWC
    ewc_enabled = any(feature in wireless_config for feature in [
        'ap role active',
        'ap capwap'
    ])

    # Device is vulnerable if it's an active EWC
    is_vulnerable = ewc_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1615. "
        "The device is a Catalyst 9100 Series AP configured as an Embedded Wireless Controller, "
        "which could allow an unauthenticated remote attacker to cause a denial of service condition "
        "through insufficient buffer allocation. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ewc-dos-g6JruHRT"
    )
