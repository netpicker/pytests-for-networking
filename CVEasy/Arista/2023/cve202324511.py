from comfy import high


@high(
    name='rule_cve202324511',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_snmp='show running-config | include snmp-server'
    ),
)
def rule_cve202324511(configuration, commands, device, devices):
    """
    This rule checks for CVE-2023-24511 vulnerability in Arista EOS devices.
    The vulnerability allows a specially crafted SNMP packet to cause a memory leak in the snmpd process,
    which can lead to process termination and memory resource exhaustion.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.24.x versions
        '4.24.0', '4.24.11M',
        # 4.25.x versions
        '4.25.0', '4.25.10M',
        # 4.26.x versions
        '4.26.0', '4.26.9M',
        # 4.27.x versions
        '4.27.0', '4.27.8.1M',
        # 4.28.x versions
        '4.28.0', '4.28.5.1M',
        # 4.29.x versions
        '4.29.0', '4.29.1F'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SNMP is configured
    snmp_config = commands.show_snmp
    snmp_enabled = 'snmp-server' in snmp_config

    # Assert that the device is not vulnerable
    assert not snmp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2023-24511. "
        "The device is running a vulnerable version AND has SNMP configured, "
        "which could allow memory leaks in the snmpd process leading to service disruption. "
        "Recommended fixes:\n"
        "- Upgrade to one of the following fixed versions:\n"
        "  * 4.29.2F or later for 4.29.x train\n"
        "  * 4.28.6M or later for 4.28.x train\n"
        "  * 4.27.9M or later for 4.27.x train\n"
        "  * 4.26.10M or later for 4.26.x train\n"
        "Workaround: Configure SNMP ACLs to restrict access:\n"
        "  snmp-server ipv4 access-list allowHosts4\n"
        "  snmp-server ipv6 access-list allowHosts6\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/17239-security-advisory-0084"
    )
