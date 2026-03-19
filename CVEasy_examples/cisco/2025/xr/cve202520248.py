from comfy import high

@high(
    name='rule_cve202520248',
    platform=['cisco_ios-xr'],
    commands=dict(show_version='show version'),
)
def rule_cve202520248(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20248 in Cisco IOS XR Software.
    A vulnerability in the installation process could allow an authenticated, local 
    attacker to bypass Cisco IOS XR Software image signature verification and load 
    unsigned software on an affected device. The attacker must have root-system 
    privileges on the affected device.
    
    This vulnerability is due to incomplete validation of files during the installation 
    of an .iso file. An attacker could exploit this vulnerability by modifying contents 
    of the .iso image and then installing and activating it on the device.
    """

    # Extract the output of the 'show version' command
    show_version_output = commands.show_version

    # Define the vulnerable software versions and trains
    # All versions 7.10 and earlier are vulnerable
    # 7.11 is vulnerable
    # 24.2 versions before 24.2.21 are vulnerable
    # 24.3 is vulnerable
    # 24.4 versions before 24.4.2 are vulnerable
    # 25.1 and later are not affected
    
    vulnerable_patterns = [
        # 7.x versions (7.10 and earlier, 7.11) - use specific patterns to avoid false matches
        'Version 7.0.', 'Version 7.1.', 'Version 7.2.', 'Version 7.3.', 'Version 7.4.', 'Version 7.5.', 
        'Version 7.6.', 'Version 7.7.', 'Version 7.8.', 'Version 7.9.', 'Version 7.10.', 'Version 7.11.',
        # 24.2 versions before 24.2.21 - add \n to avoid matching 24.2.21 with 24.2.1
        'Version 24.2.1\n', 'Version 24.2.2\n', 'Version 24.2.3\n', 'Version 24.2.4\n', 'Version 24.2.5\n',
        'Version 24.2.6\n', 'Version 24.2.7\n', 'Version 24.2.8\n', 'Version 24.2.9\n', 
        'Version 24.2.10', 'Version 24.2.11', 'Version 24.2.12', 'Version 24.2.13', 'Version 24.2.14', 
        'Version 24.2.15', 'Version 24.2.16', 'Version 24.2.17', 'Version 24.2.18', 'Version 24.2.19', 'Version 24.2.20',
        # 24.3 versions
        'Version 24.3.',
        # 24.4 versions before 24.4.2
        'Version 24.4.1\n',
    ]

    # Check if the device's software version matches vulnerable patterns
    is_vulnerable = any(pattern in show_version_output for pattern in vulnerable_patterns)

    # Assert that the device is not running a vulnerable version
    # If the device is running a vulnerable version, the test will fail
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco IOS XR Software "
        "affected by CVE-2025-20248. This vulnerability allows an authenticated, local attacker "
        "with root-system privileges to bypass image signature verification and load unsigned software. "
        "Please upgrade to a fixed release: 24.2.21, 24.4.2, or 25.1 or later. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xrsig-UY4zRUCG"
    )