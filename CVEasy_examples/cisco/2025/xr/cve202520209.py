from comfy import high

@high(
    name='rule_cve202520209',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        show_udp_brief='show udp brief'
    ),
)
def rule_cve202520209(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20209 vulnerability in Cisco IOS XR Software.
    The vulnerability in the IKEv2 function could allow an unauthenticated, remote attacker to
    prevent an affected device from processing any control plane UDP packets, resulting in a DoS condition.
    
    Affected products: NCS 540L, NCS 1004, NCS 1010, NCS 1014
    Vulnerable when IKEv2 is enabled (listening on UDP ports 500 and 4500)
    """

    # Extract command outputs
    show_version_output = commands.show_version
    show_udp_brief_output = commands.show_udp_brief

    # Define vulnerable version ranges (use specific patterns to avoid substring matches)
    vulnerable_version_patterns = []
    
    # 7.10 and earlier (excluding fixed versions)
    for major in range(1, 8):
        for minor in range(0, 11):  # 0-10 only, 7.11+ handled separately
            vulnerable_version_patterns.append(f'Version {major}.{minor}.')
    
    # 7.11.x before 7.11.21 (add \n to single-digit patches to avoid false matches)
    for patch in range(0, 10):
        vulnerable_version_patterns.append(f'Version 7.11.{patch}\n')
    for patch in range(10, 21):
        vulnerable_version_patterns.append(f'Version 7.11.{patch}')
    
    # 24.1.x (all versions)
    vulnerable_version_patterns.append('Version 24.1.')
    
    # 24.2.0 and 24.2.1 (before 24.2.2) - add \n to avoid matching 24.2.10, 24.2.11, etc.
    vulnerable_version_patterns.append('Version 24.2.0\n')
    vulnerable_version_patterns.append('Version 24.2.1\n')

    # Check if device is running a vulnerable version
    is_vulnerable_version = any(pattern in show_version_output for pattern in vulnerable_version_patterns)

    # Check if IKEv2 is enabled by looking for UDP ports 500 and 4500
    ikev2_enabled = False
    if show_udp_brief_output:
        # Check for both port 500 and 4500 in the UDP brief output
        has_port_500 = ':500' in show_udp_brief_output
        has_port_4500 = ':4500' in show_udp_brief_output
        ikev2_enabled = has_port_500 and has_port_4500

    # Device is vulnerable if running vulnerable version AND IKEv2 is enabled
    is_vulnerable = is_vulnerable_version and ikev2_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20209. "
        f"The device is running a vulnerable version of Cisco IOS XR Software with IKEv2 enabled. "
        f"An unauthenticated, remote attacker could prevent the device from processing control plane UDP packets, "
        f"resulting in a denial of service condition. "
        f"Please upgrade to a fixed release: 7.11.21, 24.2.2, or 24.3 and later. "
        f"For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xrike-9wYGpRGq"
    )