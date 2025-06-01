from comfy import high


@high(
    name='rule_cve202128504',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_tcam='show hardware tcam profile',
        show_acl='show running-config | section ip access-list'
    ),
)
def rule_cve202128504(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28504 vulnerability in Arista EOS devices.
    The vulnerability occurs on Strata family products when TCAM profile is enabled and 
    port IPv4 access-lists contain rules matching VXLAN protocol, causing subsequent rules 
    to not match IP protocol fields as expected.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.26.x versions before 4.26.4F
        '4.26.0', '4.26.1F', '4.26.2F', '4.26.3F',
        # 4.27.x versions before 4.27.1M
        '4.27.0F'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if TCAM profile feature is enabled
    tcam_output = commands.show_tcam
    tcam_enabled = 'Profile:' in tcam_output

    # Check if any ACL has VXLAN protocol matching
    acl_config = commands.show_acl
    has_vxlan_acl = 'protocol vxlan' in acl_config.lower()

    # Device is vulnerable if TCAM profile is enabled and has VXLAN protocol matching in ACLs
    is_vulnerable = tcam_enabled and has_vxlan_acl

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28504. "
        "The device is running a vulnerable version AND has TCAM profile enabled with ACLs matching VXLAN protocol, "
        "which could cause subsequent ACL rules to not match IP protocol fields correctly. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.26.4F or later for 4.26.x train\n"
        "  * 4.27.1M or later for 4.27.x train\n"
        "2. Until upgrade is complete, implement this workaround:\n"
        "  * Replace 'protocol vxlan' matches in ACLs with:\n"
        "    - protocol udp\n"
        "    - destination port 4789 (or configured VXLAN port)\n"
        "For more information, see https://www.arista.com/en/support/advisories-notices/security-advisory/15267-security-advisory-0073"
    )
