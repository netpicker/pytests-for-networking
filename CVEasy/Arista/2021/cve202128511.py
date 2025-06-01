from comfy import high


@high(
    name='rule_cve202128511',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_nat='show running-config | section ip nat',
        show_acl='show running-config | section ip access-list'
    ),
)
def rule_cve202128511(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28511 vulnerability in Arista EOS devices.
    The vulnerability allows security ACL bypass if a NAT ACL rule filter with permit action
    matches a packet flow that should be denied by a security ACL.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.24.x versions before 4.24.10
        '4.24.0', '4.24.1', '4.24.2', '4.24.3', '4.24.4', '4.24.5',
        '4.24.6', '4.24.7', '4.24.8', '4.24.9',
        # 4.25.x versions before 4.25.9
        '4.25.0', '4.25.1', '4.25.2', '4.25.3', '4.25.4', '4.25.5',
        '4.25.6', '4.25.7', '4.25.8',
        # 4.26.x versions before 4.26.6
        '4.26.0', '4.26.1', '4.26.2', '4.26.3', '4.26.4', '4.26.5',
        # 4.27.x versions before 4.27.4
        '4.27.0', '4.27.1', '4.27.2', '4.27.3'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if NAT is configured
    nat_config = commands.show_nat
    nat_enabled = 'ip nat' in nat_config.lower()

    # Check if security ACLs are configured
    acl_config = commands.show_acl
    security_acl_enabled = 'ip access-list' in acl_config.lower()

    # Device is vulnerable if both NAT and security ACLs are enabled
    is_vulnerable = nat_enabled and security_acl_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28511. "
        "The device is running a vulnerable version AND has both NAT and security ACLs configured, "
        "which could allow security ACL bypass through NAT permit rules. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.28.0 or later for 4.28.x train\n"
        "  * 4.27.4 or later for 4.27.x train\n"
        "  * 4.26.6 or later for 4.26.x train\n"
        "  * 4.25.9 or later for 4.25.x train\n"
        "  * 4.24.10 or later for 4.24.x train\n"
        "2. Until upgrade is complete, implement this workaround:\n"
        "  * Configure a NAT 'drop' ACL rule for each security ACL 'drop' rule\n"
        "  * Apply these rules to interfaces with NAT configured\n"
        "For more information, see https://www.arista.com/en/support/advisories-notices/security-advisory/15862-security-advisory-0078"
    )
