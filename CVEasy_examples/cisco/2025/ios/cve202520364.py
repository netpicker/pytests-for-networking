from comfy import high


@high(
    name='rule_cve202520364',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_wlan='show wlan all'
    ),
)
def rule_cve202520364(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20364 vulnerability in Cisco Wireless Access Point Software.
    The vulnerability is due to insufficient verification checks of incoming 802.11 action frames, which allows
    an unauthenticated, adjacent attacker to inject wireless 802.11 Device Analytics action frames with arbitrary
    information, potentially modifying Device Analytics data of valid wireless clients.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions for Catalyst 9800 Series Wireless Controller or EWC
    vulnerable_version_ranges = [
        '17.11', '17.12.0', '17.12.1', '17.12.2', '17.12.3', '17.12.4', '17.12.5',
        '17.13', '17.14', '17.15.0', '17.15.1', '17.15.2', '17.15.3',
        '17.16', '17.17'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = False
    for version in vulnerable_version_ranges:
        if version in version_output:
            version_vulnerable = True
            break

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # If version is vulnerable, check for Device Analytics configuration
    wlan_output = commands.show_wlan

    # Check if Device Analytics Advertise Support is enabled
    device_analytics_enabled = 'Advertise Support : Enabled' in wlan_output or 'Advertise Support: Enabled' in wlan_output

    # If Device Analytics is enabled, the device is vulnerable
    is_vulnerable = device_analytics_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20364. "
        "The device is running a vulnerable version AND has Device Analytics Advertise Support enabled, "
        "which makes it susceptible to 802.11 action frame injection attacks. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-action-frame-inj-QqCNcz8H"
    )