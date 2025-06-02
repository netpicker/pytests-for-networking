from comfy import high


@high(
    name='rule_cve202324513',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_sfe='show sfe status',
        show_platform='show platform cloudeos'
    ),
)
def rule_cve202324513(configuration, commands, device, devices):
    """
    This rule checks for CVE-2023-24513 vulnerability in Arista CloudEOS devices.
    The vulnerability in the Software Forwarding Engine (Sfe) can lead to a potential
    denial of service attack by sending malformed packets to the switch, causing packet
    buffer leaks that may eventually stop traffic forwarding.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.26.x versions
        '4.26.0F', '4.26.9M',
        # 4.27.x versions
        '4.27.0F', '4.27.8M',
        # 4.28.x versions
        '4.28.0F', '4.28.5M',
        # 4.29.x versions
        '4.29.0F', '4.29.1F'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if this is a CloudEOS platform
    platform_output = commands.show_platform
    is_cloudeos = 'CloudEOS' in platform_output

    # Check if SFE is enabled (default on CloudEOS)
    sfe_output = commands.show_sfe
    sfe_enabled = 'SFE enabled' in sfe_output

    # Device is vulnerable if it's CloudEOS with SFE enabled
    is_vulnerable = is_cloudeos and sfe_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2023-24513. "
        "The device is running a vulnerable version on CloudEOS platform with "
        "Software Forwarding Engine (SFE) enabled, "
        "which could allow malformed packets to cause buffer leaks and stop traffic forwarding. "
        "Recommended fixes:\n"
        "- Upgrade to one of the following fixed versions:\n"
        "  * 4.29.2F or later for 4.29.x train\n"
        "  * 4.28.6M or later for 4.28.x train\n"
        "  * 4.27.9M or later for 4.27.x train\n"
        "  * 4.26.10M or later for 4.26.x train\n"
        "- Or apply the appropriate hotfix for your version\n"
        "Note: Installing/uninstalling the hotfix will cause SFE agent to restart "
        "and stop forwarding traffic for up to 10 seconds.\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/17240-security-advisory-0085"
    )
