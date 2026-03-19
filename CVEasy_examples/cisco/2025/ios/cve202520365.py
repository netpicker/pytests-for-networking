from comfy import high
import re


def parse_version(version_str):
    """Parse version string into tuple of integers for proper comparison."""
    parts = re.split(r'[.\-]', version_str)
    result = []
    for part in parts:
        try:
            result.append(int(part))
        except ValueError:
            break
    return tuple(result)


@high(
    name='rule_cve202520365',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_ap_summary='show ap summary'
    ),
)
def rule_cve202520365(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20365 vulnerability in Cisco Access Point Software.
    The vulnerability is due to a logic error in the processing of IPv6 RA packets that are received 
    from wireless clients. An attacker could exploit this vulnerability by associating to a wireless 
    network and sending a series of crafted IPv6 RA packets to temporarily change the IPv6 gateway.
    
    Affected products:
    - 6300 Series Embedded Services Access Points (APs)
    - Aironet 1540, 1560, 1800, 2800, 3800, 4800 Series APs
    - Catalyst 9100 APs
    - Catalyst IW6300 Heavy Duty Series APs
    - Integrated APs on 1100 ISRs
    
    Vulnerable when configured for CAPWAP over IPv6.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define vulnerable version ranges for Catalyst 9800 Wireless Controller
    # Using tuples for proper numeric comparison
    vulnerable_version_ranges = [
        # 17.8 and earlier - all vulnerable
        ((17, 0), (17, 8, 99)),
        # 17.9 before 17.9.7
        ((17, 9, 0), (17, 9, 6)),
        # 17.10 - all vulnerable
        ((17, 10, 0), (17, 10, 99)),
        # 17.11 - all vulnerable
        ((17, 11, 0), (17, 11, 99)),
        # 17.12 before 17.12.5
        ((17, 12, 0), (17, 12, 4)),
        # 17.13 - all vulnerable
        ((17, 13, 0), (17, 13, 99)),
        # 17.14 - all vulnerable
        ((17, 14, 0), (17, 14, 99)),
        # 17.15 before 17.15.2
        ((17, 15, 0), (17, 15, 1)),
    ]

    # Check if the current device's software version is vulnerable
    version_vulnerable = False
    
    # Check for IOS XE version patterns
    for line in version_output.split('\n'):
        if 'Version' in line and '17.' in line:
            # Extract version number (e.g., "17.9.5" from "Cisco IOS XE Software, Version 17.9.5")
            for part in line.split():
                if part.startswith('17.'):
                    version = part.rstrip(',')
                    version_tuple = parse_version(version)
                    # Check against vulnerable ranges
                    for vuln_start, vuln_end in vulnerable_version_ranges:
                        if vuln_start <= version_tuple <= vuln_end:
                            version_vulnerable = True
                            break
                    break
        # Also check for older WLC versions (8.x and earlier are end-of-life but vulnerable)
        elif 'Version' in line and any(v in line for v in ['8.', '7.', '6.']):
            version_vulnerable = True

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if APs are configured for CAPWAP over IPv6
    ap_summary_output = commands.show_ap_summary

    # Check if any AP is using IPv6 address (indicated by presence of colons in IP address)
    ipv6_configured = False
    
    for line in ap_summary_output.split('\n'):
        # Skip header lines
        if 'AP Name' in line or 'Number of APs' in line or 'CC =' in line:
            continue
        # Look for IPv6 addresses (contain colons)
        if '::' in line or (line.count(':') >= 2 and 'Registered' in line):
            ipv6_configured = True
            break

    # Device is vulnerable if running vulnerable version AND has CAPWAP over IPv6 configured
    is_vulnerable = version_vulnerable and ipv6_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20365. "
        "The device is running a vulnerable version of Cisco Access Point Software AND has "
        "Access Points configured for CAPWAP over IPv6, which makes it susceptible to IPv6 gateway "
        "modification attacks via crafted IPv6 RA packets. This could lead to intermittent packet loss. "
        "Upgrade to a fixed release: 17.9.7, 17.12.5, 17.15.2, or 17.16+. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ap-ipv6-gw-tUAzpn9O"
    )