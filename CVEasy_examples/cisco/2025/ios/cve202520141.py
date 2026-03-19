from comfy import high


@high(
    name='rule_cve202520141',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_install_active='show install active summary'
    ),
)
def rule_cve202520141(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20141 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incorrect handling of packets that are punted to the route processor.
    An unauthenticated, adjacent attacker can exploit this by sending traffic that must be handled
    by the Linux stack on the route processor, causing control plane traffic to stop working,
    resulting in a denial of service (DoS) condition.
    
    Affected products running IOS XR Release 7.9.2:
    - IOS XR White box (IOSXRWBD)
    - Network Convergence System (NCS) 540 Series Routers (NCS540-iosxr base image)
    - NCS 5500 Series
    - NCS 5700 Series (NCS5500-iosxr base image)
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    install_output = commands.show_install_active
    
    # Combine outputs for version checking
    combined_output = version_output + '\n' + install_output
    
    # Check if the device is running IOS XR (not IOS)
    is_iosxr = 'IOS XR' in combined_output or 'Cisco IOS XR Software' in combined_output
    
    # If not IOS XR, device is not vulnerable
    if not is_iosxr:
        return
    
    # Check if running the specific vulnerable version 7.9.2
    version_vulnerable = '7.9.2' in combined_output and 'Version 7.9.2' in combined_output
    
    # Check if device is one of the affected platforms
    affected_platforms = [
        'IOSXRWBD',  # IOS XR White box
        'NCS-540',   # NCS 540 Series
        'NCS540',
        'NCS-5500',  # NCS 5500 Series
        'NCS5500',
        'NCS-5700',  # NCS 5700 Series
        'NCS5700'
    ]
    
    platform_affected = any(platform in combined_output for platform in affected_platforms)
    
    # Device is vulnerable if it's running version 7.9.2 on an affected platform
    is_vulnerable = version_vulnerable and platform_affected
    
    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20141. "
        "The device is running Cisco IOS XR Software Release 7.9.2 on an affected platform, "
        "which makes it susceptible to DoS attacks through incorrect handling of punted packets. "
        "An unauthenticated, adjacent attacker can cause control plane traffic to stop working. "
        "Apply the SMU on 7.9.2 or migrate to a fixed release. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr792-bWfVDPY"
    )