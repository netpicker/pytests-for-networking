from comfy import high


@high(
    name='rule_cve202324509',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_module='show module',
        show_redundancy='show redundancy status'
    ),
)
def rule_cve202324509(configuration, commands, device, devices):
    """
    This rule checks for CVE-2023-24509 vulnerability in Arista EOS devices.
    The vulnerability allows privilege escalation when an unprivileged user logs into
    the standby supervisor as root on devices with redundant supervisor modules and
    RPR/SSO redundancy protocol configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.23.x versions
        '4.23.0', '4.23.13M',
        # 4.24.x versions
        '4.24.0', '4.24.10M',
        # 4.25.x versions
        '4.25.0', '4.25.9M',
        # 4.26.x versions
        '4.26.0', '4.26.8M',
        # 4.27.x versions
        '4.27.0', '4.27.6M',
        # 4.28.x versions
        '4.28.0', '4.28.3M'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check for redundant supervisor modules
    module_output = commands.show_module
    has_standby_supervisor = 'Standby supervisor' in module_output

    # Check redundancy protocol configuration
    redundancy_output = commands.show_redundancy
    redundancy_configured = any(protocol in redundancy_output for protocol in [
        'Route Processor Redundancy',
        'Stateful Switchover'
    ])

    # Device is vulnerable if it has both conditions
    is_vulnerable = has_standby_supervisor and redundancy_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2023-24509. "
        "The device is running a vulnerable version AND has redundant supervisor modules with RPR/SSO configured, "
        "which could allow privilege escalation via root access to standby supervisor. "
        "Recommended fixes:\n"
        "- Upgrade to one of the following fixed versions:\n"
        "  * 4.28.4M or later for 4.28.x train\n"
        "  * 4.27.7M or later for 4.27.x train\n"
        "  * 4.26.9M or later for 4.26.x train\n"
        "  * 4.25.10M or later for 4.25.x train\n"
        "  * 4.24.11M or later for 4.24.x train\n"
        "- Or apply the hotfix for supported versions\n"
        "Workaround: Disable SSH CLI command in unprivileged mode using RBAC\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/16985-security-advisory-0082"
    )
