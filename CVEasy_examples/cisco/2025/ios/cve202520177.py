from comfy import high


@high(
    name='rule_cve202520177',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_install_active='show install active summary'
    ),
)
def rule_cve202520177(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20177 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incomplete validation of files in the boot verification process,
    which could allow an authenticated, local attacker with root-system privileges to bypass
    Cisco IOS XR image signature verification and load unverified software on an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    install_output = commands.show_install_active
    
    # Combine outputs for version detection
    combined_output = version_output + '\n' + install_output

    # Check if device is running IOS XR (not IOS)
    is_ios_xr = 'IOS XR' in combined_output or 'Cisco IOS XR Software' in combined_output
    
    # If not IOS XR, device is not vulnerable
    if not is_ios_xr:
        return

    # Check for vulnerable product families
    vulnerable_products = [
        '8000 Series',
        'NCS540L',
        'NCS 1010',
        'NCS 1014',
        'NCS5700',
        'NCS-5700'
    ]
    
    is_vulnerable_product = any(product in combined_output for product in vulnerable_products)
    
    # If not a vulnerable product, device is not vulnerable
    if not is_vulnerable_product:
        return

    # Define vulnerable version ranges
    # Versions 7.10 and earlier are vulnerable
    # Versions 7.11 before 7.11.21 are vulnerable
    # Versions 24.2 before 24.2.2 are vulnerable
    # Versions 24.3 before 24.3.2 are vulnerable
    # Versions 24.4 before 24.4.1 are vulnerable
    
    version_vulnerable = False
    
    # Check for 7.10 and earlier (vulnerable)
    if any(ver in combined_output for ver in [
        'Version 7.10', 'Version 7.9', 'Version 7.8', 'Version 7.7',
        'Version 7.6', 'Version 7.5', 'Version 7.4', 'Version 7.3',
        'Version 7.2', 'Version 7.1.', 'Version 7.0', 'Version 6.'
    ]):
        version_vulnerable = True
    
    # Check for 7.11 before 7.11.21 (vulnerable)
    if 'Version 7.11' in combined_output:
        if not any(fixed in combined_output for fixed in [
            '7.11.21', '7.11.22', '7.11.23', '7.11.24', '7.11.25'
        ]):
            version_vulnerable = True
    
    # Check for 24.2 before 24.2.2 (vulnerable)
    if 'Version 24.2' in combined_output:
        if '24.2.1' in combined_output or combined_output.count('24.2') > combined_output.count('24.2.'):
            version_vulnerable = True
    
    # Check for 24.3 before 24.3.2 (vulnerable)
    if 'Version 24.3' in combined_output:
        if '24.3.1' in combined_output or combined_output.count('24.3') > combined_output.count('24.3.'):
            version_vulnerable = True
    
    # Check for 24.4 before 24.4.1 (vulnerable)
    if 'Version 24.4.0' in combined_output:
        version_vulnerable = True

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20177. "
        "The device is running a vulnerable version of Cisco IOS XR Software on an affected platform. "
        "This vulnerability allows an authenticated, local attacker with root-system privileges to bypass "
        "image signature verification and load unverified software. "
        "Upgrade to a fixed release: 7.11.21, 24.2.2, 24.3.2, or 24.4.1 or later. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xr-verii-bypass-HhPwQRvx"
    )