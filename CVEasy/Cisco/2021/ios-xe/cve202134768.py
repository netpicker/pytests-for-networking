from comfy import high


@high(
    name='rule_cve202134768',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_capwap='show running-config | include ap capwap|wireless management'
    ),
)
def rule_cve202134768(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34768 vulnerability in Cisco IOS XE Software for Catalyst 9000
    Family Wireless Controllers. Multiple vulnerabilities in the CAPWAP protocol processing could
    allow an unauthenticated, remote attacker to cause a denial of service condition through
    malformed CAPWAP packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a Catalyst 9000 Series Wireless Controller
    platform_output = commands.check_platform
    vulnerable_platforms = [
        'C9800', 'Catalyst 9800',
        'C9K-WLC', 'C9K Wireless Controller'
    ]
    is_wireless_controller = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_wireless_controller:
        return

    # Check for CAPWAP configuration
    capwap_config = commands.check_capwap

    # Check if wireless management/CAPWAP is enabled
    wireless_enabled = any(feature in capwap_config for feature in [
        'ap capwap',
        'wireless management'
    ])

    # Device is vulnerable if wireless management is enabled on a Cat9K WLC
    is_vulnerable = wireless_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-34768. "
        "The device is a Catalyst 9000 Family Wireless Controller with CAPWAP enabled, which could allow "
        "an unauthenticated remote attacker to cause a denial of service condition through malformed "
        "CAPWAP packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-dos-gmNjdKOY"
    )
