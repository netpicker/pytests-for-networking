from comfy import high


@high(
    name='rule_cve20211611',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_eogre='show running-config | include tunnel mode eogre|wireless management'
    ),
)
def rule_cve20211611(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1611 vulnerability in Cisco IOS XE Software for Catalyst 9800
    Series Wireless Controllers. The vulnerability in the EoGRE packet processing could allow an
    unauthenticated, remote attacker to cause a denial of service (DoS) condition through
    malformed EoGRE packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a vulnerable platform (Catalyst 9800 Family or Cat9k with embedded wireless)
    platform_output = commands.check_platform
    vulnerable_platforms = [
        'C9800', 'C9200', 'C9300',
        'C9400', 'C9500', 'C9600'
    ]
    is_vulnerable_platform = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_vulnerable_platform:
        return

    # Check for EoGRE tunnel and wireless configuration
    eogre_config = commands.check_eogre

    # Check if EoGRE tunneling is enabled
    eogre_enabled = any(feature in eogre_config for feature in [
        'tunnel mode eogre',
        'wireless management interface'
    ])

    # Device is vulnerable if EoGRE or wireless management is enabled
    is_vulnerable = eogre_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1611. "
        "The device is a Catalyst 9800 Series controller or Cat9k with embedded wireless and has EoGRE "
        "or wireless management enabled, which could allow an unauthenticated remote attacker to cause "
        "a denial of service condition through malformed EoGRE packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-gre-6u4ELzAT"
    )
