from comfy import high

@high(
    name='rule_cve202559984',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559984(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59984 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in Global Search that,
    when visited by another user, enables the attacker to execute commands with the
    target's permissions, including an administrator (XSS vulnerability).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is a Junos Space installation
    # Junos Space is a separate product from Junos OS, but we check for indicators
    is_junos_space = 'Junos Space' in version_output or 'Space' in version_output

    # If not Junos Space, device is not vulnerable
    if not is_junos_space:
        return

    # All versions before 24.1R4 are vulnerable
    # Check if running a vulnerable version
    version_vulnerable = False
    
    # Extract version number
    if 'Space' in version_output:
        # Check for versions before 24.1R4
        vulnerable_version_patterns = [
            '23.', '22.', '21.', '20.', '19.', '18.', '17.', '16.', '15.',
            '24.1R1', '24.1R2', '24.1R3'
        ]
        
        version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)
        
        # If we find 24.1R4 or later, it's not vulnerable
        if '24.1R4' in version_output or '24.2' in version_output or '25.' in version_output:
            version_vulnerable = False
        elif '24.1' in version_output:
            # If it's 24.1 but not R4 or later, it's vulnerable
            version_vulnerable = True

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-59984. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks through Global Search. "
        "An attacker can inject script tags that execute commands with the target user's permissions. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59984"
    )