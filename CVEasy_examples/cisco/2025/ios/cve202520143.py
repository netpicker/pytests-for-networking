from comfy import high


@high(
    name='rule_cve202520143',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_install_active='show install active summary'
    ),
)
def rule_cve202520143(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20143 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to insufficient verification of modules in the software load process,
    which could allow an authenticated, local attacker with high privileges to bypass the Secure Boot
    functionality and load unverified software on an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    install_output = commands.show_install_active
    
    # Check if this is IOS XR (not IOS, IOS XE, or NX-OS)
    is_ios_xr = 'IOS XR' in version_output or 'iosxr' in version_output.lower()
    
    # If not IOS XR, device is not vulnerable
    if not is_ios_xr:
        return
    
    # Check for vulnerable device models (include both space and dash variants)
    vulnerable_models = [
        'ASR 9', 'ASR-9',
        'IOS XRv 9000', 'IOS-XRv-9000',
        'NCS 540', 'NCS-540',
        'NCS 560', 'NCS-560',
        'NCS 1', 'NCS-1',
        'NCS 5', 'NCS-5'
    ]
    
    device_is_vulnerable_model = any(model in version_output for model in vulnerable_models)
    
    # If not a vulnerable model, return
    if not device_is_vulnerable_model:
        return
    
    # Parse version to check if it's vulnerable
    # Vulnerable: 7.8 and earlier, 7.9.0
    # Fixed: 7.9.1 and later, 7.10 and later
    version_vulnerable = False
    
    # Extract version number
    import re
    version_match = re.search(r'Version\s+(\d+)\.(\d+)\.(\d+)', version_output)
    if version_match:
        major = int(version_match.group(1))
        minor = int(version_match.group(2))
        patch = int(version_match.group(3))
        
        # Check if version is vulnerable
        if major < 7:
            version_vulnerable = True
        elif major == 7:
            if minor < 9:
                # 7.8 and earlier
                version_vulnerable = True
            elif minor == 9 and patch == 0:
                # 7.9.0 is vulnerable
                version_vulnerable = True
            # 7.9.1+ and 7.10+ are not vulnerable
    else:
        # If we can't parse version, check for known vulnerable version strings
        vulnerable_version_patterns = [
            r'7\.[0-8]\.',  # 7.0 through 7.8
            r'7\.9\.0',      # 7.9.0
            r'[1-6]\.\d+\.'  # Any version 6.x or earlier
        ]
        version_vulnerable = any(re.search(pattern, version_output) for pattern in vulnerable_version_patterns)
    
    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20143. "
        "The device is running a vulnerable version of Cisco IOS XR Software (7.8 or earlier, or 7.9.0) "
        "which has insufficient verification of modules in the software load process. "
        "This could allow an authenticated, local attacker with high privileges to bypass Secure Boot "
        "functionality and load unverified software. "
        "Upgrade to IOS XR 7.9.1 or later to remediate this vulnerability. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-lkm-zNErZjbZ"
    )