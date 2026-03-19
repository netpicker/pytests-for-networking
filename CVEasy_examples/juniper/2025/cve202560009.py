from comfy import high

@high(
    name='rule_cve202560009',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202560009(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-60009 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the CLI Configlet page
    that enables XSS attacks to execute commands with the target's permissions.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Junos Space
    # Junos Space versions before 24.1R4 are vulnerable
    is_junos_space = 'Junos Space' in version_output or 'junos-space' in version_output.lower()

    # If not Junos Space, device is not vulnerable
    if not is_junos_space:
        return

    # Define vulnerable version patterns for Junos Space
    # All versions before 24.1R4 are vulnerable
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
        f"Device {device.name} is vulnerable to CVE-2025-60009. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks in the CLI Configlet page. "
        "An attacker can inject script tags that execute commands with the target user's permissions, including administrator. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-60009"
    )