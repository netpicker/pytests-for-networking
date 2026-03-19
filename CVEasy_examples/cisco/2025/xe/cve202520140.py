from comfy import high

@high(
    name='rule_cve202520140',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_wireless_ipv6=r'show run all | include wireless\ ipv6\ client',
        show_wncd='show platform software wlc process wncd'
    ),
)
def rule_cve202520140(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20140 vulnerability in Cisco IOS XE Software
    for Wireless LAN Controllers (WLCs).
    
    A vulnerability in the Wireless Network Control daemon (wncd) could allow an unauthenticated,
    adjacent wireless attacker to cause a denial of service (DoS) condition by sending a series
    of IPv6 network requests from an associated wireless IPv6 client.
    
    The vulnerability is due to improper memory management and affects devices with wireless
    IPv6 client support enabled (which is enabled by default).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions based on Cisco IOS XE for WLC products
    # These versions are vulnerable if wireless IPv6 client support is enabled
    vulnerable_versions = [
        # 16.x versions
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b', '16.3.6', '16.3.7', '16.3.8',
        '16.3.9', '16.3.10', '16.3.11',
        '16.4.1', '16.4.2', '16.4.3',
        '16.5.1', '16.5.1a', '16.5.1b', '16.5.2', '16.5.3',
        '16.6.1', '16.6.2', '16.6.3', '16.6.4', '16.6.5', '16.6.4a', '16.6.5a', '16.6.6', '16.6.7', '16.6.8',
        '16.6.9', '16.6.10',
        '16.7.1', '16.7.2', '16.7.3',
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.2', '16.8.3',
        '16.9.1', '16.9.2', '16.9.1a', '16.9.1b', '16.9.1s', '16.9.3', '16.9.4', '16.9.3a', '16.9.5', '16.9.5f',
        '16.9.6', '16.9.7', '16.9.8',
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1e', '16.10.2', '16.10.3',
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s',
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.2', '16.12.2a', '16.12.3', '16.12.8', '16.12.2s',
        '16.12.1t', '16.12.4', '16.12.3s', '16.12.3a', '16.12.4a', '16.12.5', '16.12.6', '16.12.5a', '16.12.5b',
        '16.12.6a', '16.12.7', '16.12.9', '16.12.10', '16.12.10a', '16.12.11',
        # 17.x versions
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.3',
        '17.2.1', '17.2.1r', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.2a', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b',
        '17.3.4c', '17.3.5a', '17.3.5b', '17.3.7', '17.3.8', '17.3.8a',
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a',
        '17.6.1', '17.6.2', '17.6.1a', '17.6.3', '17.6.3a', '17.6.4', '17.6.5', '17.6.6', '17.6.6a', '17.6.5a',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', '17.9.4', '17.9.4a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.11.99SW',
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a', '17.12.3', '17.12.4',
        '17.13.1', '17.13.1a', '17.13.2', '17.13.3',
        '17.14.1', '17.14.1a', '17.14.2',
        '17.15.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if wireless IPv6 client support is enabled
    wireless_ipv6_output = commands.show_wireless_ipv6
    wireless_ipv6_enabled = 'wireless ipv6 client' in wireless_ipv6_output and 'no wireless ipv6 client' not in wireless_ipv6_output

    # Check if wncd process is running (indicates WLC functionality)
    wncd_output = commands.show_wncd
    wncd_running = 'wncd' in wncd_output

    # Device is vulnerable if:
    # 1. Running a vulnerable version
    # 2. Wireless IPv6 client support is enabled (default)
    # 3. WNCD process is running (WLC functionality)
    if wireless_ipv6_enabled and wncd_running:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20140. "
            "The device is running a vulnerable version of Cisco IOS XE Software for WLC "
            "with wireless IPv6 client support enabled. An unauthenticated, adjacent wireless "
            "attacker could cause a denial of service condition by sending a series of IPv6 "
            "network requests. Mitigation: Disable wireless IPv6 clients using 'no wireless ipv6 client' "
            "if the feature is not in use, or upgrade to a fixed software version. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-wncd-p6Gvt6HL"
        )
    else:
        # If wireless IPv6 is disabled or wncd is not running, device is not vulnerable
        return