from comfy import high

@high(
    name='rule_cve202559998',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559998(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59998 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the Archive Log screen
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

    # Define vulnerable version pattern - all versions before 24.1R4
    # Check for versions 24.1R4 and later (non-vulnerable)
    is_fixed_version = False
    
    # Check for 24.1R4 or later
    if '24.1R4' in version_output or '24.2' in version_output or '24.3' in version_output or '24.4' in version_output:
        is_fixed_version = True
    
    # Check for versions 25.x and later
    for major_version in range(25, 30):
        if f'{major_version}.' in version_output:
            is_fixed_version = True
            break

    # If version is fixed, device is not vulnerable
    if is_fixed_version:
        return

    # Check if version appears to be before 24.1R4
    version_vulnerable = False
    vulnerable_major_versions = ['19.', '20.', '21.', '22.', '23.']
    
    for ver in vulnerable_major_versions:
        if ver in version_output:
            version_vulnerable = True
            break
    
    # Check for 24.1 versions before R4
    if '24.1R1' in version_output or '24.1R2' in version_output or '24.1R3' in version_output:
        version_vulnerable = True

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-59998. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks through the Archive Log screen. "
        "An attacker can inject script tags that execute commands with the target user's permissions, including administrator. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59998"
    )