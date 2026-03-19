from comfy import high


@high(
    name='rule_cve202520198',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_privilege='show privilege'
    ),
)
def rule_cve202520198(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20198 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient input validation when processing specific configuration commands.
    An authenticated, local attacker with privilege level 15 could exploit this vulnerability to elevate
    privileges to root on the underlying operating system of an affected device.
    
    Note: This vulnerability requires the attacker to already have privilege level 15 (configuration mode access).
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
    # until patched according to the advisory's Fixed Software section)
    # The advisory indicates this affects IOS XE Software but does not specify exact vulnerable versions
    # in the provided text. We check for IOS XE presence as the primary indicator.
    
    # Check for common vulnerable version patterns
    # Since specific vulnerable versions are not listed in the advisory excerpt,
    # we flag IOS XE devices for manual review or patch verification
    version_vulnerable = is_ios_xe

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check privilege level - vulnerability requires privilege level 15
    privilege_output = commands.show_privilege
    
    # The vulnerability exists in the software itself when privilege level 15 access is available
    # Since we cannot determine from configuration alone if the vulnerability has been patched,
    # we check if this is a vulnerable IOS XE version
    
    # Extract version number for more specific checking
    # Look for version patterns like "Version 17.3.3" or "Version 16.12.5"
    import re
    version_match = re.search(r'Version\s+(\d+\.\d+(?:\.\d+)?(?:\([^)]+\))?)', version_output)
    
    if version_match:
        version_string = version_match.group(1)
        
        # Based on Cisco advisory pattern, versions that need patching are vulnerable
        # Without specific fixed version info in the excerpt, we flag for verification
        # Typically, older versions are more likely vulnerable
        
        # Extract major version
        major_version_match = re.match(r'(\d+)\.', version_string)
        if major_version_match:
            major_version = int(major_version_match.group(1))
            
            # IOS XE versions 16.x and 17.x are commonly affected in recent advisories
            # Flag these for manual verification against Cisco Software Checker
            is_vulnerable = major_version >= 16 and major_version <= 17
            
            # Assert that the device is not vulnerable
            assert not is_vulnerable, (
                f"Device {device.name} may be vulnerable to CVE-2025-20198. "
                f"The device is running Cisco IOS XE Software version {version_string}, which may be affected by "
                "a privilege escalation vulnerability. An authenticated attacker with privilege level 15 could "
                "exploit insufficient input validation in configuration commands to elevate privileges to root. "
                "Please verify the software version against Cisco's Software Checker and apply patches if available. "
                "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-privesc-su7scvdp"
            )