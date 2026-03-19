from comfy import high

@high(
    name='rule_cve202559987',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559987(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59987 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the arbitrary device 
    search field that enables XSS attacks, allowing execution of commands with the 
    target's permissions, including an administrator.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions - all versions before 24.1R4
    # Check for Junos Space version pattern
    is_junos_space = 'Junos Space' in version_output or 'junos-space' in version_output.lower()
    
    if not is_junos_space:
        return

    # Parse version to check if it's before 24.1R4
    version_vulnerable = False
    
    # Check for versions before 24.1R4
    vulnerable_version_patterns = [
        '23.4', '23.3', '23.2', '23.1',
        '22.', '21.', '20.', '19.', '18.', '17.', '16.', '15.',
        '24.1R1', '24.1R2', '24.1R3'
    ]
    
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)
    
    # Check if version is 24.1R4 or later (not vulnerable)
    if '24.1R4' in version_output or '24.2' in version_output or '25.' in version_output:
        version_vulnerable = False
        return

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if Junos Space is configured/enabled
    config_output = commands.show_config_junos_space
    has_junos_space_config = bool(config_output.strip()) and 'junos-space' in config_output.lower()

    # Assert that the device is not vulnerable
    assert not (version_vulnerable and is_junos_space), (
        f"Device {device.name} is vulnerable to CVE-2025-59987. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks through the arbitrary device search field. "
        "An attacker can inject script tags that execute commands with the target's permissions, including administrator privileges. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59987"
    )