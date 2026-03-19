from comfy import high


@high(
    name='rule_cve202520248',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_install_active='show install active summary'
    ),
)
def rule_cve202520248(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20248 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incomplete validation of files during the installation of an .iso file,
    which could allow an authenticated, local attacker with root-system privileges to bypass image
    signature verification and load unsigned software on an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    install_output = commands.show_install_active
    
    # Check if this is actually IOS XR (not IOS or IOS XE)
    is_iosxr = 'IOS XR' in version_output or 'Cisco IOS XR Software' in version_output
    
    # If not IOS XR, device is not vulnerable
    if not is_iosxr:
        return
    
    # Check for vulnerable device types (include both space and dash variants)
    vulnerable_devices = [
        'ASR 9000', 'ASR-9000',
        'ASR9K', 'ASR-9K',
        'IOSXRWBD',
        'IOS XRv 9000', 'IOS-XRv-9000',
        'XRv9000', 'XRv-9000',
        'NCS 540', 'NCS-540',
        'NCS 560', 'NCS-560',
        'NCS 1001', 'NCS-1001',
        'NCS 1002', 'NCS-1002',
        'NCS 1004', 'NCS-1004',
        'NCS 5000', 'NCS-5000',
        'NCS 5500', 'NCS-5500',
        'NCS 5700', 'NCS-5700',
        'NCS 6000', 'NCS-6000'
    ]
    
    # Check for non-vulnerable device types (include both space and dash variants)
    non_vulnerable_devices = [
        '8000 Series', '8000-Series',
        'NCS 540L', 'NCS-540L',
        'NCS 1010', 'NCS-1010',
        'NCS 1014', 'NCS-1014'
    ]
    
    # Check if device is in non-vulnerable list
    device_not_vulnerable = any(dev_type in version_output for dev_type in non_vulnerable_devices)
    
    if device_not_vulnerable:
        return
    
    # Check if device is in vulnerable list
    device_vulnerable = any(dev_type in version_output for dev_type in vulnerable_devices)
    
    # If we can't determine device type, assume vulnerable for safety
    if not device_vulnerable:
        # Check install output as well
        device_vulnerable = any(dev_type in install_output for dev_type in vulnerable_devices)
    
    # List of vulnerable software versions
    vulnerable_version_patterns = [
        '7.10',
        '7.11',
        '24.2.1',
        '24.2.2',
        '24.3',
        '24.4.1'
    ]
    
    # List of fixed software versions
    fixed_version_patterns = [
        '24.2.21',
        '24.4.2',
        '25.1'
    ]
    
    # Check if running a fixed version
    version_fixed = any(version in version_output or version in install_output 
                       for version in fixed_version_patterns)
    
    if version_fixed:
        return
    
    # Check if running a vulnerable version
    version_vulnerable = any(version in version_output or version in install_output 
                            for version in vulnerable_version_patterns)
    
    # Additional check for 7.10 and earlier (any 7.x before 7.10 is also vulnerable)
    if 'Version 7.' in version_output or 'Version 6.' in version_output or 'Version 5.' in version_output:
        version_vulnerable = True
    
    # Device is vulnerable if it's a vulnerable device type and running vulnerable version
    is_vulnerable = device_vulnerable and version_vulnerable
    
    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20248. "
        "The device is running a vulnerable version of Cisco IOS XR Software that allows "
        "an authenticated attacker with root-system privileges to bypass image signature verification "
        "and load unsigned software. Upgrade to a fixed release: 24.2.21, 24.4.2, or 25.1+. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xrsig-UY4zRUCG"
    )