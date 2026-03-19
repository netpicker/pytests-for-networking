from comfy import high

@high(
    name='rule_cve202560000',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202560000(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-60000 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the Generate Report page
    that enables XSS attacks to execute commands with the target's permissions.
    This issue affects all versions of Junos Space before 24.1R4.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is a Junos Space installation
    config_output = commands.show_config_junos_space
    is_junos_space = 'junos-space' in config_output.lower() or 'space' in version_output.lower()

    # If not Junos Space, device is not vulnerable
    if not is_junos_space:
        return

    # Define vulnerable version patterns - all versions before 24.1R4
    vulnerable_version_patterns = []
    
    # All versions 23.x and below
    for major in range(10, 24):
        vulnerable_version_patterns.append(f'{major}.')
    
    # Version 24.1R1, 24.1R2, 24.1R3
    vulnerable_version_patterns.extend(['24.1R1', '24.1R2', '24.1R3'])

    # Check if the current version is vulnerable
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)

    # Check if version is 24.1R4 or later (not vulnerable)
    is_patched = '24.1R4' in version_output or '24.2' in version_output or '25.' in version_output

    # If patched version, device is not vulnerable
    if is_patched:
        return

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-60000. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks in the Generate Report page. "
        "An attacker can inject script tags that execute commands with the target user's permissions, "
        "including administrator privileges. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-60000"
    )