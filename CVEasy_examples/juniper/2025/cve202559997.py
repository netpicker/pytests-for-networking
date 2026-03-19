from comfy import high

@high(
    name='rule_cve202559997',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559997(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59997 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the CLI Configlets pages
    that enable execution of commands with the target's permissions through XSS.
    This issue affects all versions of Junos Space before 24.1R4.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Junos Space
    is_junos_space = 'Junos Space' in version_output or 'junos-space' in version_output.lower()

    if not is_junos_space:
        return

    # Define vulnerable version patterns for Junos Space
    # All versions before 24.1R4 are vulnerable
    vulnerable = False

    # Extract version number
    import re
    version_match = re.search(r'(\d+)\.(\d+)R(\d+)', version_output)
    
    if version_match:
        major = int(version_match.group(1))
        minor = int(version_match.group(2))
        release = int(version_match.group(3))
        
        # Check if version is before 24.1R4
        if major < 24:
            vulnerable = True
        elif major == 24 and minor < 1:
            vulnerable = True
        elif major == 24 and minor == 1 and release < 4:
            vulnerable = True

    # Assert that the device is not vulnerable
    assert not vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-59997. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks in CLI Configlets pages. "
        "An attacker can inject script tags that execute commands with the target user's permissions. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59997"
    )