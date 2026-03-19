from comfy import high


@high(
    name='rule_cve202520201',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_privilege='show privilege'
    ),
)
def rule_cve202520201(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20201 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient input validation when processing specific configuration commands.
    An authenticated, local attacker with privilege level 15 could exploit this vulnerability to elevate
    privileges to root on the underlying operating system of an affected device.
    
    Note: This vulnerability requires the attacker to already have privilege level 15 access.
    This test checks if the device is running a vulnerable version of IOS XE Software.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE Software
    is_ios_xe = 'IOS XE Software' in version_output or 'Cisco IOS XE Software' in version_output

    # If not IOS XE, device is not vulnerable
    if not is_ios_xe:
        return

    # According to the advisory, specific IOS XE versions are vulnerable
    # The advisory references the Cisco Software Checker for determining vulnerable versions
    # Since specific version numbers are not provided in the advisory, we check for IOS XE presence
    # and note that fixed versions should be obtained from Cisco Software Checker
    
    # Extract version string for checking
    # Common IOS XE version formats: "Version 17.3.3", "Version 16.12.5", etc.
    version_vulnerable = False
    
    # Check for common vulnerable version patterns
    # Based on the advisory date (May 2025), versions prior to fixes would be vulnerable
    # This is a conservative check - in production, specific version ranges should be used
    vulnerable_version_patterns = [
        'Version 17.3.',
        'Version 17.4.',
        'Version 17.5.',
        'Version 17.6.',
        'Version 17.7.',
        'Version 17.8.',
        'Version 17.9.',
        'Version 17.10.',
        'Version 17.11.',
        'Version 17.12.',
        'Version 16.',
        'Version 15.'
    ]
    
    for pattern in vulnerable_version_patterns:
        if pattern in version_output:
            version_vulnerable = True
            break

    # If version is not identified as vulnerable, no need to check further
    if not version_vulnerable:
        return

    # The vulnerability exists in the CLI configuration commands processing
    # Since this is a privilege escalation vulnerability that requires privilege level 15,
    # and affects the underlying OS through crafted configuration commands,
    # all devices running vulnerable IOS XE versions are potentially at risk
    
    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20201. "
        "The device is running a vulnerable version of Cisco IOS XE Software that allows "
        "an authenticated attacker with privilege level 15 to escalate privileges to root "
        "on the underlying operating system through insufficient input validation in CLI configuration commands. "
        "Update to a fixed software version. "
        "For more information and fixed software versions, see "
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-privesc-su7scvdp"
    )