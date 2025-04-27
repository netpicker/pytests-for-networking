from comfy import high


@high(
    name='rule_cve202427889',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_config='show running-config | include report.*online.*access'
    ),
)
def rule_cve202427889(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-27889 vulnerability in Arista Edge Threat Management - NG Firewall.
    The vulnerability allows SQL injection in the reporting application that can lead to command execution
    with elevated privileges when a user has advanced report application access rights.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions up to and including 17.0 are vulnerable
        '17.0'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if any Report Users have Online Access enabled
    config_output = commands.show_config
    online_access_enabled = 'report' in config_output and 'online access' in config_output.lower()

    # Assert that the device is not vulnerable
    assert not online_access_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-27889. "
        "The device is running a vulnerable version and has Report Users with Online Access enabled, "
        "which could allow SQL injection attacks leading to command execution with elevated privileges. "
        "Recommended fixes:\n"
        "- Upgrade to version 17.1\n"
        "- For version 17.0, apply the hotfix\n"
        "- Workaround: Disable Online Access for all Report Users\n"
        "For more information, see https://www.arista.com/en/support/advisories-notices/security-advisory/19038-security-advisory-0093"
    )
