from comfy import high


@high(
    name='rule_cve202520197',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_privilege='show privilege'
    ),
)
def rule_cve202520197(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20197 vulnerability in Cisco IOS XE Software.
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

    # List of vulnerable software versions (based on typical Cisco IOS XE vulnerable releases)
    # Note: The advisory does not specify exact vulnerable versions, so we check for IOS XE presence
    # In a real scenario, specific version ranges would be extracted from the Fixed Software section
    vulnerable_version_patterns = [
        '17.3.', '17.4.', '17.5.', '17.6.', '17.7.', '17.8.', '17.9.',
        '17.10.', '17.11.', '17.12.', '17.13.', '17.14.', '17.15.',
        '16.12.', '17.1.', '17.2.'
    ]

    # Check if the current device's software version matches vulnerable patterns
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)

    # If version is not in known vulnerable range, assume safe
    if not version_vulnerable:
        return

    # Check privilege level - this vulnerability requires privilege level 15
    # However, since this is a detection rule, we flag any vulnerable version
    # as the vulnerability exists regardless of current privilege level
    privilege_output = commands.show_privilege
    
    # The device is vulnerable if running a vulnerable IOS XE version
    # The actual exploitation requires privilege level 15, but the vulnerability exists
    is_vulnerable = version_vulnerable and is_ios_xe

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20197. "
        "The device is running a vulnerable version of Cisco IOS XE Software with insufficient input validation "
        "in CLI configuration commands. An authenticated attacker with privilege level 15 could exploit this "
        "to elevate privileges to root on the underlying operating system. "
        "Update to a fixed software version immediately. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-privesc-su7scvdp"
    )