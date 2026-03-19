from comfy import high

@high(
    name='rule_cve202559983',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559983(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59983 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the Template Definition page
    through Cross-site Scripting (XSS), enabling execution of commands with the target's permissions.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is a Junos Space installation
    # Junos Space is identified by specific version patterns or configuration
    is_junos_space = 'Junos Space' in version_output or 'space' in version_output.lower()

    # If not Junos Space, device is not vulnerable
    if not is_junos_space:
        return

    # Define vulnerable version pattern - all versions before 24.1R4
    # Extract version number if present
    vulnerable = False
    
    # Check for versions before 24.1R4
    if 'Space' in version_output:
        # Parse version - vulnerable if < 24.1R4
        if '24.1R4' not in version_output:
            # Check if it's an older version
            version_indicators = [
                '23.', '22.', '21.', '20.', '19.', '18.', '17.', '16.', '15.',
                '24.1R1', '24.1R2', '24.1R3'
            ]
            vulnerable = any(indicator in version_output for indicator in version_indicators)

    # If version is not vulnerable, exit early
    if not vulnerable:
        return

    # Check if Junos Space web interface is accessible/configured
    config_output = commands.show_config_junos_space
    has_junos_space_config = bool(config_output.strip())

    # Assert that the device is not vulnerable
    assert not (vulnerable and is_junos_space), (
        f"Device {device.name} is vulnerable to CVE-2025-59983. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks in the Template Definition page. "
        "An attacker can inject script tags to execute commands with the target user's permissions, including administrator. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59983"
    )