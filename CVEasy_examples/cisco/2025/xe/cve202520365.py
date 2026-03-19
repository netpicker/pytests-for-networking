from comfy import medium

@medium(
    name='rule_cve202520365',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_ap_summary='show ap summary'
    ),
)
def rule_cve202520365(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20365 vulnerability in Cisco Access Point Software.
    
    A vulnerability in the IPv6 Router Advertisement (RA) packet processing of Cisco Access Point 
    Software could allow an unauthenticated, adjacent attacker to modify the IPv6 gateway on an 
    affected device.
    
    The vulnerability affects devices running vulnerable Cisco IOS XE releases with APs configured 
    for CAPWAP over IPv6.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define vulnerable version ranges and their fixed versions
    # Based on the advisory table
    vulnerable_version_ranges = {
        '17.8': None,  # Migrate to fixed release
        '17.9': '17.9.7',  # Fixed in 17.9.7
        '17.10': None,  # Migrate to fixed release
        '17.11': None,  # Migrate to fixed release
        '17.12': '17.12.5',  # Fixed in 17.12.5
        '17.13': None,  # Migrate to fixed release
        '17.14': None,  # Migrate to fixed release
        '17.15': '17.15.2',  # Fixed in 17.15.2
    }
    
    # Versions 17.16, 17.17, 17.18 are not vulnerable
    non_vulnerable_versions = ['17.16', '17.17', '17.18']

    # Check if running a non-vulnerable version
    if any(version in version_output for version in non_vulnerable_versions):
        return

    # Check if running a vulnerable version
    version_vulnerable = False
    for vuln_version in vulnerable_version_ranges.keys():
        if vuln_version in version_output:
            fixed_version = vulnerable_version_ranges[vuln_version]
            if fixed_version:
                # Check if running the fixed version or later
                if fixed_version not in version_output:
                    version_vulnerable = True
                    break
            else:
                # No fix available for this version, must migrate
                version_vulnerable = True
                break

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if any APs are configured for CAPWAP over IPv6
    ap_summary_output = commands.show_ap_summary
    
    # Look for IPv6 addresses in the AP summary output
    # IPv6 addresses contain colons
    ipv6_configured = False
    if ap_summary_output:
        lines = ap_summary_output.split('\n')
        for line in lines:
            # Skip header lines
            if 'AP Name' in line or 'Number of APs' in line or 'CC =' in line:
                continue
            # Check if line contains an IPv6 address (contains multiple colons)
            if line.count(':') >= 2:
                # Verify it's in the IP Address column by checking format
                parts = line.split()
                for part in parts:
                    if ':' in part and part.count(':') >= 2:
                        ipv6_configured = True
                        break
            if ipv6_configured:
                break

    # Device is vulnerable if running vulnerable version AND has APs with IPv6 CAPWAP
    if ipv6_configured:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20365. "
            "The device is running a vulnerable version of Cisco IOS XE Software AND has Access Points "
            "configured for CAPWAP over IPv6. An unauthenticated, adjacent attacker could modify the IPv6 "
            "gateway on the affected device by sending crafted IPv6 RA packets. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ap-ipv6-gw-tUAzpn9O"
        )