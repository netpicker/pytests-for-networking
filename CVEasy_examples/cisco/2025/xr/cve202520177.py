from comfy import high

@high(
    name='rule_cve202520177',
    platform=['cisco_ios-xr'],
    commands=dict(show_version='show version'),
)
def rule_cve202520177(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20177 in Cisco IOS XR Software.
    
    A vulnerability in the boot process of Cisco IOS XR Software could allow an 
    authenticated, local attacker to bypass Cisco IOS XR image signature verification 
    and load unverified software on an affected device. To exploit this vulnerability, 
    the attacker must have root-system privileges on the affected device.
    
    This vulnerability is due to incomplete validation of files in the boot verification 
    process. An attacker could exploit this vulnerability by manipulating the system 
    configuration options to bypass some of the integrity checks that are performed 
    during the boot process.
    
    Affected Products:
    - 8000 Series Routers
    - Network Convergence System (NCS) 540 Series Routers (NCS540L images)
    - NCS 1010
    - NCS 1014
    - NCS 5700 Series Fixed-Port Routers (NCS5700 images)
    
    Vulnerable Versions:
    - 7.10 and earlier (migrate to fixed release)
    - 7.11.x (fixed in 7.11.21)
    - 24.2.x (fixed in 24.2.2)
    - 24.3.x (fixed in 24.3.2)
    - 24.4.x (fixed in 24.4.1)
    """

    # Extract the output of the 'show version' command
    show_version_output = commands.show_version

    # Define vulnerable version patterns
    # Versions 7.10 and earlier are vulnerable
    vulnerable_710_and_earlier = [
        '7.0.', '7.1.', '7.2.', '7.3.', '7.4.', '7.5.', 
        '7.6.', '7.7.', '7.8.', '7.9.', '7.10.'
    ]
    
    # 7.11.x versions before 7.11.21 are vulnerable
    # Single-digit patches need \n to avoid matching 7.11.21 with 7.11.2
    vulnerable_711_versions = [
        '7.11.1\n', '7.11.2\n', '7.11.3\n', '7.11.4\n', '7.11.5\n',
        '7.11.6\n', '7.11.7\n', '7.11.8\n', '7.11.9\n', '7.11.10',
        '7.11.11', '7.11.12', '7.11.13', '7.11.14', '7.11.15',
        '7.11.16', '7.11.17', '7.11.18', '7.11.19', '7.11.20'
    ]
    
    # 24.2.x versions before 24.2.2 are vulnerable
    vulnerable_242_versions = ['24.2.1']
    
    # 24.3.x versions before 24.3.2 are vulnerable
    vulnerable_243_versions = ['24.3.1']
    
    # 24.4.x versions before 24.4.1 are vulnerable (24.4.0 if exists)
    vulnerable_244_versions = ['24.4.0']

    # Check if the device is running a vulnerable version
    is_vulnerable = False
    
    # Check 7.10 and earlier
    for version_pattern in vulnerable_710_and_earlier:
        if version_pattern in show_version_output:
            is_vulnerable = True
            break
    
    # Check 7.11.x vulnerable versions
    if not is_vulnerable:
        for version in vulnerable_711_versions:
            if version in show_version_output:
                is_vulnerable = True
                break
    
    # Check 24.2.x vulnerable versions
    if not is_vulnerable:
        for version in vulnerable_242_versions:
            if version in show_version_output:
                is_vulnerable = True
                break
    
    # Check 24.3.x vulnerable versions
    if not is_vulnerable:
        for version in vulnerable_243_versions:
            if version in show_version_output:
                is_vulnerable = True
                break
    
    # Check 24.4.x vulnerable versions
    if not is_vulnerable:
        for version in vulnerable_244_versions:
            if version in show_version_output:
                is_vulnerable = True
                break

    # Assert that the device is not running a vulnerable version
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco IOS XR Software "
        "affected by CVE-2025-20177. This vulnerability allows an authenticated, local attacker "
        "with root-system privileges to bypass Cisco IOS XR image signature verification and load "
        "unverified software on the device. "
        "Please upgrade to a fixed release: 7.11.21, 24.2.2, 24.3.2, or 24.4.1 or later. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xr-verii-bypass-HhPwQRvx"
    )