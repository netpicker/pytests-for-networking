from comfy import high

@high(
    name='rule_cve202559985',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559985(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59985 vulnerability in Juniper Networks Junos Space.
    The vulnerability is a Cross-site Scripting (XSS) issue in the Purging Policy page
    that allows an attacker to inject script tags and execute commands with the target's
    permissions, including administrator privileges.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is a Junos Space installation
    # Junos Space versions before 24.1R4 are vulnerable
    is_junos_space = 'Junos Space' in version_output or 'junos-space' in version_output.lower()

    # If not Junos Space, device is not vulnerable
    if not is_junos_space:
        return

    # Check for vulnerable Junos Space versions (before 24.1R4)
    # Vulnerable version patterns
    vulnerable = False
    
    # Check for versions before 24.1R4
    if 'Junos Space' in version_output:
        # Extract version number
        import re
        version_match = re.search(r'(\d+)\.(\d+)R(\d+)', version_output)
        if version_match:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            release = int(version_match.group(3))
            
            # Vulnerable if version < 24.1R4
            if major < 24:
                vulnerable = True
            elif major == 24 and minor < 1:
                vulnerable = True
            elif major == 24 and minor == 1 and release < 4:
                vulnerable = True

    # Assert that the device is not vulnerable
    assert not vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-59985. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks on the Purging Policy page. "
        "An attacker can inject script tags to execute commands with the target's permissions, including administrator. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59985"
    )