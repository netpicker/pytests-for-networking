from comfy import medium

@medium(
    name='rule_cve202520364',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_wlan='show wlan all',
    ),
)
def rule_cve202520364(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20364 vulnerability in Cisco 
    Wireless Access Point Software where an unauthenticated, adjacent attacker 
    could inject wireless 802.11 action frames with arbitrary information.

    The vulnerability affects Cisco APs running vulnerable software versions with
    Device Analytics enabled (Advertise Support: Enabled).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions based on the advisory
    # Versions 17.11 and earlier, 17.12.0-17.12.5, 17.13-17.17 are vulnerable
    # 17.12.6, 17.15.4, and 17.18+ are fixed
    vulnerable_version_ranges = [
        # 17.11 and earlier (checking for common vulnerable versions)
        '17.1.', '17.2.', '17.3.', '17.4.', '17.5.', '17.6.', '17.7.', 
        '17.8.', '17.9.', '17.10.', '17.11.',
        # 17.12.0 through 17.12.5 (vulnerable)
        '17.12.1', '17.12.2', '17.12.3', '17.12.4', '17.12.5',
        # 17.13 series (vulnerable)
        '17.13.',
        # 17.14 series (vulnerable)
        '17.14.',
        # 17.15.0 through 17.15.3 (vulnerable, 17.15.4+ fixed)
        '17.15.1', '17.15.2', '17.15.3',
        # 17.16 series (vulnerable)
        '17.16.',
        # 17.17 series (vulnerable)
        '17.17.',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if Device Analytics is enabled on any WLAN
    wlan_output = commands.show_wlan
    
    # Look for Device Analytics configuration with Advertise Support enabled
    device_analytics_enabled = False
    
    if 'Device Analytics' in wlan_output and 'Advertise Support' in wlan_output:
        # Parse the output to check if any WLAN has Device Analytics enabled
        lines = wlan_output.split('\n')
        for i, line in enumerate(lines):
            if 'Device Analytics' in line:
                # Check the next few lines for "Advertise Support : Enabled"
                for j in range(i, min(i + 5, len(lines))):
                    if 'Advertise Support' in lines[j] and 'Enabled' in lines[j]:
                        device_analytics_enabled = True
                        break
            if device_analytics_enabled:
                break

    # If Device Analytics is enabled, the device is vulnerable
    assert not device_analytics_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-20364. "
        "The device is running a vulnerable version of Cisco AP Software AND has Device Analytics "
        "Advertise Support enabled on one or more WLANs. An unauthenticated, adjacent attacker could "
        "inject 802.11 Device Analytics action frames with arbitrary information. "
        "Upgrade to a fixed release: 17.12.6, 17.15.4, or 17.18+. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-action-frame-inj-QqCNcz8H"
    )