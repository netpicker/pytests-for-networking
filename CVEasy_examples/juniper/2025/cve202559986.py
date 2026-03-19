from comfy import high

@high(
    name='rule_cve202559986',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559986(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59986 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the input fields in Model Devices
    that, when visited by another user, enables the attacker to execute commands with the target's permissions.
    This is a Cross-site Scripting (XSS) vulnerability.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Junos Space (not regular Junos OS)
    # Junos Space versions are in format like "24.1R1", "24.1R2", etc.
    is_junos_space = 'Space' in version_output or 'space' in version_output

    # If not Junos Space, this CVE doesn't apply
    if not is_junos_space:
        return

    # Define vulnerable version patterns
    # All versions before 24.1R4 are vulnerable
    vulnerable = False
    
    # Extract version number
    import re
    version_match = re.search(r'(\d+)\.(\d+)R(\d+)', version_output)
    
    if version_match:
        major = int(version_match.group(1))
        minor = int(version_match.group(2))
        release = int(version_match.group(3))
        
        # Vulnerable if version is before 24.1R4
        if major < 24:
            vulnerable = True
        elif major == 24 and minor < 1:
            vulnerable = True
        elif major == 24 and minor == 1 and release < 4:
            vulnerable = True

    # Assert that the device is not vulnerable
    assert not vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-59986. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks in Model Devices input fields. "
        "An attacker can inject script tags that execute commands with the target user's permissions. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59986"
    )