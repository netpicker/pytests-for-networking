from comfy import high

@high(
    name='rule_cve202559996',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559996(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59996 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the Configuration View page
    through Cross-site Scripting (XSS), enabling execution of commands with the target's permissions.
    This issue affects all versions of Junos Space before 24.1R4.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is a Junos Space installation
    is_junos_space = 'Junos Space' in version_output or 'junos-space' in version_output.lower()

    # If not Junos Space, device is not vulnerable
    if not is_junos_space:
        return

    # Define vulnerable version patterns - all versions before 24.1R4
    vulnerable_version_patterns = [
        '19.', '20.', '21.', '22.', '23.',
        '24.1R1', '24.1R2', '24.1R3'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)

    # Check if version is 24.1R4 or later (not vulnerable)
    if '24.1R4' in version_output or '24.2' in version_output or '25.' in version_output:
        version_vulnerable = False

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-59996. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks in the Configuration View page. "
        "An attacker can inject script tags that execute commands with the target user's permissions, "
        "including administrator privileges. Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59996"
    )