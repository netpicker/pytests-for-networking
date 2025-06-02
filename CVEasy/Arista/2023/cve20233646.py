from comfy import high


@high(
    name='rule_cve20233646',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_monitor='show monitor session',
        show_config='show running-config | section monitor'
    ),
)
def rule_cve20233646(configuration, commands, device, devices):
    """
    This rule checks for CVE-2023-3646 vulnerability in Arista EOS devices.
    The vulnerability can trigger a kernel panic and cause system reload when mirroring
    to multiple destinations is configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.28.x versions
        '4.28.2F', '4.28.3F', '4.28.4F', '4.28.5F', '4.28.5.1M',
        # 4.29.x versions
        '4.29.0F', '4.29.1F'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check for multiple destination ports in monitor sessions
    monitor_output = commands.show_monitor
    config_output = commands.show_config

    # Check if any monitor session has multiple destinations configured
    multiple_destinations = False
    if 'Session' in monitor_output:
        # Count destination ports in active sessions
        dest_ports = len([line for line in monitor_output.splitlines() if ':  active' in line])
        multiple_destinations = dest_ports > 1

    # Assert that the device is not vulnerable
    assert not multiple_destinations, (
        f"Device {device.name} is vulnerable to CVE-2023-3646. "
        "The device is running a vulnerable version AND has mirroring to multiple destinations configured, "
        "which could trigger a kernel panic and cause system reload. "
        "Recommended fixes:\n"
        "- Upgrade to 4.28.6M or later for 4.28.x train\n"
        "- Upgrade to 4.29.2F or later for 4.29.x train\n"
        "- Workaround: Remove mirroring configuration to multiple destinations\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/18042-security-advisory-0088"
    )
