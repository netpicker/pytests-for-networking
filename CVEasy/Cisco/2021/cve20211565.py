from comfy import high


@high(
    name='rule_cve20211565',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_wireless='show running-config | include wireless|capwap'
    ),
)
def rule_cve20211565(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1565 vulnerability in Cisco IOS XE Software for Catalyst 9000
    Family Wireless Controllers. Multiple vulnerabilities in the CAPWAP protocol processing could
    allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition through
    malformed CAPWAP packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a vulnerable platform (Catalyst 9000 Family)
    platform_output = commands.check_platform
    vulnerable_platforms = [
        'C9200', 'C9300', 'C9400',
        'C9500', 'C9600', 'C9800'
    ]
    is_vulnerable_platform = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_vulnerable_platform:
        return

    # Check for wireless controller configuration
    wireless_config = commands.check_wireless

    # Check if wireless controller functionality is enabled
    wireless_enabled = any(feature in wireless_config for feature in [
        'wireless management interface',
        'wireless mobility controller',
        'capwap'
    ])

    # Device is vulnerable if wireless controller features are enabled
    is_vulnerable = wireless_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1565. "
        "The device is a Catalyst 9000 Series switch with wireless controller features enabled, "
        "which could allow an unauthenticated remote attacker to cause a denial of service condition "
        "through malformed CAPWAP packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-dos-gmNjdKOY"
    )
