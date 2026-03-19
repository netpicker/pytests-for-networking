from comfy import high

@high(
    name='rule_cve202520202',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_ap_profile='show running-config | section ap profile'
    ),
)
def rule_cve202520202(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20202 vulnerability in Cisco IOS XE 
    Wireless Controller Software where an unauthenticated, adjacent attacker could cause 
    a denial of service (DoS) condition.

    The vulnerability is due to insufficient input validation of access point (AP) Cisco 
    Discovery Protocol (CDP) neighbor reports when they are processed by the wireless 
    controller. An attacker could exploit this vulnerability by sending a crafted CDP 
    packet to an AP.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (all versions prior to fixed releases)
    # Based on Cisco advisory, this affects Catalyst 9800 series running vulnerable IOS XE
    vulnerable_versions = [
        # 17.x versions
        '17.1.1', '17.1.2', '17.1.3',
        '17.2.1', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.4', '17.3.5', '17.3.6', '17.3.7', '17.3.8',
        '17.4.1', '17.4.2',
        '17.5.1',
        '17.6.1', '17.6.2', '17.6.3', '17.6.4', '17.6.5', '17.6.6',
        '17.7.1', '17.7.2',
        '17.8.1',
        '17.9.1', '17.9.2', '17.9.3', '17.9.4',
        '17.10.1',
        '17.11.1',
        '17.12.1', '17.12.2',
        '17.13.1',
        '17.14.1',
        '17.15.1',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check AP profile configuration for CDP status
    ap_profile_output = commands.show_ap_profile

    # If there are no AP profiles configured, device is not vulnerable
    if not ap_profile_output or 'ap profile' not in ap_profile_output:
        return

    # Parse AP profiles to check if CDP is enabled on any profile
    # CDP is enabled by default unless explicitly disabled with "no cdp"
    profiles = ap_profile_output.split('ap profile ')
    
    cdp_enabled_on_any_profile = False
    
    for profile in profiles:
        if not profile.strip():
            continue
        
        # Check if this profile has "no cdp" configured
        if 'no cdp' not in profile:
            # CDP is enabled (default behavior)
            cdp_enabled_on_any_profile = True
            break

    # If CDP is enabled on at least one AP profile, the device is vulnerable
    assert not cdp_enabled_on_any_profile, (
        f"Device {device.name} is vulnerable to CVE-2025-20202. "
        "The device is running a vulnerable version of Cisco IOS XE Wireless Controller Software "
        "AND has CDP enabled on at least one AP Join profile. An unauthenticated, adjacent attacker "
        "could send crafted CDP packets to an AP to cause a denial of service condition. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-cdp-dos-fpeks9K"
    )