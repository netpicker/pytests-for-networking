from comfy import high

@high(
    name='rule_cve202559978',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559978(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59978 vulnerability in Juniper Networks Junos Space.
    The vulnerability is a Cross-site Scripting (XSS) issue that allows an attacker to store
    script tags directly in web pages that, when viewed by another user, enable the attacker
    to execute commands with the target's administrative permissions.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Junos Space
    is_junos_space = 'Junos Space' in version_output or 'junos-space' in version_output.lower()

    if not is_junos_space:
        return

    # Define vulnerable versions - all versions before 24.1R4
    vulnerable_version_prefixes = [
        '19.', '20.', '21.', '22.', '23.',
        '24.1R1', '24.1R2', '24.1R3'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_version_prefixes)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for Junos Space configuration
    config_output = commands.show_config_junos_space
    has_junos_space_config = 'junos-space' in config_output.lower() or len(config_output.strip()) > 0

    # Assert that the device is not vulnerable
    assert not (version_vulnerable and (is_junos_space or has_junos_space_config)), (
        f"Device {device.name} is vulnerable to CVE-2025-59978. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4), "
        "which is susceptible to Cross-site Scripting (XSS) attacks that allow attackers to execute "
        "commands with administrative permissions. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59978"
    )