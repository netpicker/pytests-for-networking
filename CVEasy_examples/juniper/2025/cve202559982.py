from comfy import high

@high(
    name='rule_cve202559982',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559982(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59982 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the dashboard search field
    that enables XSS attacks to execute commands with the target's permissions.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Junos Space (not regular Junos OS)
    # Junos Space has specific version format
    is_junos_space = 'Junos Space' in version_output or 'space' in version_output.lower()

    # If not Junos Space, device is not affected
    if not is_junos_space:
        return

    # Define vulnerable versions - all versions before 24.1R4
    # Check for versions that are vulnerable
    vulnerable_version_patterns = [
        '19.', '20.', '21.', '22.', '23.',
        '24.1R1', '24.1R2', '24.1R3'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)

    # Check if version is 24.1R4 or later (not vulnerable)
    if '24.1R4' in version_output or '24.2' in version_output or '25.' in version_output:
        version_vulnerable = False

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if Junos Space is configured/enabled
    config_output = commands.show_config_junos_space
    junos_space_enabled = bool(config_output.strip()) and 'junos-space' in config_output.lower()

    # Assert that the device is not vulnerable
    assert not (version_vulnerable and is_junos_space), (
        f"Device {device.name} is vulnerable to CVE-2025-59982. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks through the dashboard search field. "
        "An attacker can inject script tags that execute commands with the target user's permissions, including administrator. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59982"
    )