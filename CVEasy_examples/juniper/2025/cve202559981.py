from comfy import high

@high(
    name='rule_cve202559981',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559981(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59981 vulnerability in Juniper Networks Junos Space.
    The vulnerability is a Cross-site Scripting (XSS) issue in the Device Template Definition page
    that allows an attacker to inject script tags and execute commands with the target's permissions.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Junos Space (not regular Junos OS)
    # Junos Space has different versioning format
    is_junos_space = 'Space' in version_output or 'space' in version_output

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

    # Check if Junos Space web interface is accessible/configured
    config_output = commands.show_config_junos_space
    has_junos_space_config = 'junos-space' in config_output or len(config_output.strip()) > 0

    # For Junos Space, if it's installed and running a vulnerable version, it's vulnerable
    # The web interface is typically enabled by default on Junos Space
    is_vulnerable = version_vulnerable and is_junos_space

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-59981. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4) "
        "which is susceptible to Cross-site Scripting (XSS) attacks in the Device Template Definition page. "
        "An attacker can inject script tags that execute commands with the target user's permissions, including administrator. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59981"
    )