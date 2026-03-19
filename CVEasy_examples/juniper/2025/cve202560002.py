from comfy import high

@high(
    name='rule_cve202560002',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202560002(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-60002 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the Template Definitions page
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
    # Check for versions 24.1R4 and later (not vulnerable)
    is_fixed_version = False
    
    # Check for 24.1R4 or later
    if '24.1R4' in version_output or '24.2' in version_output or '24.3' in version_output or '24.4' in version_output:
        is_fixed_version = True
    elif '25.' in version_output or '26.' in version_output or '27.' in version_output:
        is_fixed_version = True
    
    # Extract major version to check if it's before 24.1R4
    version_vulnerable = not is_fixed_version and is_junos_space

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-60002. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks in the Template Definitions page. "
        "An attacker can inject script tags that execute commands with the target user's permissions, including administrator. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-60002"
    )