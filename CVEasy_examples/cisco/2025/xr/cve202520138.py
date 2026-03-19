from comfy import high

@high(
    name='rule_cve202520138',
    platform=['cisco_ios-xr'],
    commands=dict(show_version='show version'),
)
def rule_cve202520138(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20138 in Cisco IOS XR Software.
    
    A vulnerability in the CLI of Cisco IOS XR Software could allow an authenticated,
    local attacker to execute arbitrary commands as root on the underlying operating
    system of an affected device. This vulnerability is due to insufficient validation
    of user arguments that are passed to specific CLI commands.
    
    Affected: Cisco IOS XR 64-bit Software versions 24.1 and earlier, 24.2 (before 24.2.21), 24.3
    Fixed: 24.2.21 (future release), 24.4 and later
    """

    # Extract the output of the 'show version' command
    show_version_output = commands.show_version

    # Parse version from show version output
    # IOS XR version format is typically like "Version 24.2.1" or "Cisco IOS XR Software, Version 24.2.1"
    import re
    version_match = re.search(r'Version\s+(\d+)\.(\d+)\.?(\d+)?', show_version_output)
    
    if not version_match:
        # Cannot determine version, assume not vulnerable
        return

    major = int(version_match.group(1))
    minor = int(version_match.group(2))
    patch = int(version_match.group(3)) if version_match.group(3) else 0

    # Check if version is vulnerable
    is_vulnerable = False
    
    # 24.1 and earlier are vulnerable
    if major < 24:
        is_vulnerable = True
    elif major == 24:
        if minor < 2:
            # 24.1 and earlier
            is_vulnerable = True
        elif minor == 2:
            # 24.2 versions before 24.2.21 are vulnerable
            if patch < 21:
                is_vulnerable = True
        elif minor == 3:
            # 24.3 is vulnerable
            is_vulnerable = True
        # 24.4 and later are not affected

    # Assert that the device is not running a vulnerable version
    # This vulnerability affects all configurations of IOS XR 64-bit Software
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco IOS XR Software (Version {major}.{minor}.{patch}). "
        "This device is affected by CVE-2025-20138, a CLI privilege escalation vulnerability that allows "
        "authenticated local attackers to execute arbitrary commands as root. "
        "Please upgrade to a fixed release (24.2.21 or later, or 24.4+) to mitigate this vulnerability. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-priv-esc-GFQjxvOF"
    )