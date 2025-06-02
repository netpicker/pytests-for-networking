from comfy import high


@high(
    name='rule_cve20244578',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_config='show running-config'
    ),
)
def rule_cve20244578(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-4578 vulnerability in Arista Wireless Access Points.
    The vulnerability allows privilege escalation via spawning a bash shell when authenticated 
    as the "config" user via SSH. The spawned shell can obtain root privileges.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 13.0.2.x versions
        '13.0.2-28-vv1002',
        # 15.x versions are all vulnerable
        '15.0', '15.1', '15.2', '15.3', '15.4', '15.5', '15.6', '15.7', '15.8', '15.9',
        # 16.x versions up to the vulnerable version
        '16.1.051-vv6'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-4578. "
        "The device is running a vulnerable version that allows privilege escalation "
        "via spawning a bash shell when authenticated as the 'config' user. "
        "Upgrade to one of the following fixed versions:\n"
        "- 13.0.2-28-vv1101 or later for 13.0.2.x\n"
        "- 16.1.0-51-vv703 or later for 16.x\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/19844-security-advisory-0098"
    )
