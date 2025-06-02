from comfy import high


@high(
    name='rule_cve202324512',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version detail | grep TerminAttr-core',
        show_daemon='show daemon TerminAttr',
        show_daemon_config='show running-config | section daemon TerminAttr'
    ),
)
def rule_cve202324512(configuration, commands, device, devices):
    """
    This rule checks for CVE-2023-24512 vulnerability in Arista EOS devices.
    The vulnerability allows an authorized attacker with gNMI permissions to craft requests
    that could update arbitrary configurations in the switch when the Streaming Telemetry
    Agent (TerminAttr) is enabled with gNMI access.
    """
    # Extract the TerminAttr version from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # Specific version
        'v1.23.0',
        # Version ranges
        'v1.19.', 'v1.20.', 'v1.21.', 'v1.22.0', 'v1.22.1',
        'v1.24.0', 'v1.24.1', 'v1.24.2', 'v1.24.3'
    ]

    # Check if the current version matches any vulnerable version patterns
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if TerminAttr daemon is running
    daemon_output = commands.show_daemon
    daemon_running = 'running with PID' in daemon_output

    # Check if gNMI access is configured
    daemon_config = commands.show_daemon_config
    gnmi_enabled = '-grpcaddr=' in daemon_config and '-grpcreadonly' not in daemon_config

    # Device is vulnerable if daemon is running and gNMI is enabled without read-only mode
    is_vulnerable = daemon_running and gnmi_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2023-24512. "
        "The device is running a vulnerable version of TerminAttr AND has the daemon running "
        "with gNMI access enabled without read-only mode. "
        "Recommended fixes:\n"
        "1. Upgrade TerminAttr:\n"
        "  * Version 1.25.0 or later\n"
        "  * Version 1.22.2 or later for 1.22.x train\n"
        "  * Version 1.19.6 or later for 1.19.x train\n"
        "2. Or upgrade EOS to a version with fixed TerminAttr:\n"
        "  * 4.29.2F or later (includes TerminAttr 1.25.0+)\n"
        "  * 4.28.6M or later (includes TerminAttr 1.22.2+)\n"
        "  * 4.27.9M or later (includes TerminAttr 1.19.6+)\n"
        "  * 4.26.10M or later (includes TerminAttr 1.19.6+)\n"
        "Workaround: Configure gRPC read-only mode:\n"
        "  daemon TerminAttr\n"
        "    exec /usr/bin/TerminAttr -grpcreadonly -grpcaddr=... <other options...>\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/17250-security-advisory-0086"
    )
