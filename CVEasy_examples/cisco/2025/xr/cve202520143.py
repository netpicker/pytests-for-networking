from comfy import high

@high(
    name='rule_cve202520143',
    platform=['cisco_ios-xr'],
    commands=dict(show_version='show version'),
)
def rule_cve202520143(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20143 in Cisco IOS XR Software.
    A vulnerability in the boot process could allow an authenticated, local attacker 
    with high privileges to bypass the Secure Boot functionality and load unverified 
    software on an affected device.
    
    This vulnerability affects versions 7.8 and earlier, with 7.9.1 being the first 
    fixed release in the 7.9 train. Versions 7.10 and later are not affected.
    """

    # Extract the output of the 'show version' command
    show_version_output = commands.show_version or ''

    # Define the vulnerable software versions (7.8 and earlier)
    # 7.9.0 is vulnerable, 7.9.1+ is fixed
    # 7.10+ is not affected
    vulnerable_versions = [
        # 7.0.x versions
        '7.0.1', '7.0.2', '7.0.3', '7.0.4', '7.0.5',
        # 7.1.x versions
        '7.1.1', '7.1.2', '7.1.3', '7.1.4', '7.1.5',
        # 7.2.x versions
        '7.2.0', '7.2.1', '7.2.2', '7.2.3', '7.2.4', '7.2.5',
        # 7.3.x versions
        '7.3.0', '7.3.1', '7.3.2', '7.3.3', '7.3.4', '7.3.5', '7.3.15',
        # 7.4.x versions
        '7.4.0', '7.4.1', '7.4.2', '7.4.3', '7.4.4', '7.4.5',
        # 7.5.x versions
        '7.5.0', '7.5.1', '7.5.2', '7.5.3', '7.5.4', '7.5.5',
        # 7.6.x versions
        '7.6.0', '7.6.1', '7.6.2', '7.6.3', '7.6.4', '7.6.5',
        # 7.7.x versions
        '7.7.0', '7.7.1', '7.7.2', '7.7.21',
        # 7.8.x versions
        '7.8.0', '7.8.1', '7.8.2', '7.8.3', '7.8.4', '7.8.5',
        # 7.9.0 is vulnerable, 7.9.1+ is fixed
        '7.9.0',
    ]

    # Check if the device's software version is listed as vulnerable
    is_vulnerable = any(version in show_version_output for version in vulnerable_versions)

    # Assert that the device is not running a vulnerable version
    # If the device is running a vulnerable version, the test will fail
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco IOS XR Software. "
        "This vulnerability (CVE-2025-20143) could allow an authenticated, local attacker "
        "with high privileges to bypass the Secure Boot functionality and load unverified software. "
        "Please upgrade to version 7.9.1 or later to mitigate this vulnerability. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-lkm-zNErZjbZ"
    )