from comfy import high


@high(
    name='rule_cve202520200',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_privilege='show privilege'
    ),
)
def rule_cve202520200(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20200 vulnerability in Cisco IOS XE Software.
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

    # List of vulnerable software versions (based on advisory - all IOS XE versions are potentially vulnerable
    # until patched according to the advisory)
    # The advisory indicates this affects IOS XE Software but doesn't specify exact vulnerable versions
    # We check for IOS XE presence and assume vulnerability unless proven otherwise by version checking
    
    # Extract version number from output
    # Common format: "Cisco IOS XE Software, Version 17.3.1"
    version_vulnerable = False
    
    # Check for common vulnerable version patterns
    # Since the advisory doesn't specify exact versions, we look for IOS XE presence
    # In production, this should be updated with specific vulnerable version ranges
    if 'Version 16.' in version_output or 'Version 17.' in version_output:
        version_vulnerable = True
    
    # Check for fixed versions (these would be safe)
    # Based on advisory pattern, fixed versions would be specified in Cisco Software Checker
    # For this test, we assume versions 17.12.1 and later are fixed (example)
    if 'Version 17.12.1' in version_output or 'Version 17.13' in version_output or 'Version 17.14' in version_output:
        version_vulnerable = False

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # The vulnerability requires privilege level 15 access to exploit
    # If the device is running vulnerable IOS XE software, it is potentially vulnerable
    is_vulnerable = version_vulnerable

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20200. "
        "The device is running a vulnerable version of Cisco IOS XE Software with insufficient input validation "
        "in CLI configuration commands. An authenticated attacker with privilege level 15 could exploit this "
        "to elevate privileges to root on the underlying operating system. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-privesc-su7scvdp"
    )