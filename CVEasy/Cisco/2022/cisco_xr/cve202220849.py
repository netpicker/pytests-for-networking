from comfy import high


@high(
    name='rule_cve202220849',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_pppoe='show running-config | include bba-group pppoe|pppoe enable'
    ),
)
def rule_cve202220849(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20849 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to improper handling of error conditions within specific PPPoE packet
    sequences in the Broadband Network Gateway feature. An unauthenticated, adjacent attacker could
    exploit this vulnerability by sending a sequence of specific PPPoE packets from controlled CPE,
    causing the PPPoE process to continually restart and resulting in a denial of service condition.
    """
    # List of vulnerable versions
    vulnerable_versions = [
        '6.5.1', '6.5.2', '6.5.3', '6.5.15', '6.6.1', '6.6.2', '6.6.3', '6.6.4', '6.6.25',
        '6.7.1', '6.7.2', '6.7.3', '6.7.35', '6.8.1', '6.8.2', '6.9.1',
        '7.0.1', '7.0.2', '7.0.90', '7.1.1', '7.1.2', '7.1.3', '7.1.15', '7.1.25',
        '7.2.1', '7.2.2', '7.3.1', '7.3.2', '7.3.3', '7.3.4', '7.4.1', '7.4.2',
        '7.5.1'
    ]

    # Extract the version information
    version_output = commands.show_version

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check PPPoE configuration
    pppoe_output = commands.check_pppoe

    # Check if PPPoE is configured
    pppoe_configured = any(feature in pppoe_output for feature in [
        'bba-group pppoe',
        'pppoe enable'
    ])

    # Assert that the device is not vulnerable
    assert not pppoe_configured, (
        f"Device {device.name} is vulnerable to CVE-2022-20849. "
        "The device is running a vulnerable version with PPPoE enabled, "
        "which could allow an adjacent attacker to cause a denial of service through crafted PPPoE packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-bng-Gmg5Gxt"
    )
