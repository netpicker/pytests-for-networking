from comfy import high


@high(
    name='rule_cve202128505',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_acl='show running-config | section ip access-list',
        show_interfaces='show running-config | section interface'
    ),
)
def rule_cve202128505(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28505 vulnerability in Arista EOS devices.
    The vulnerability occurs when VXLAN match rules in IPv4 access-lists are applied to
    ingress L2/L3 ports or SVIs, causing subsequent ACL rules to ignore IP protocol fields.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.26.x versions before 4.26.4M
        '4.26.0', '4.26.1F', '4.26.2F', '4.26.3M',
        # 4.27.x versions before 4.27.1F
        '4.27.0F'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if any ACL has VXLAN protocol matching
    acl_config = commands.show_acl
    has_vxlan_acl = 'protocol vxlan' in acl_config.lower()

    # Check if ACLs are applied to ingress L2/L3 ports or SVIs
    interface_config = commands.show_interfaces
    has_ingress_acl = any(keyword in interface_config.lower() for keyword in [
        'ip access-group',
        'ipv4 access-group'
    ])

    # Device is vulnerable if it has VXLAN ACLs applied to ingress interfaces
    is_vulnerable = has_vxlan_acl and has_ingress_acl

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28505. "
        "The device is running a vulnerable version AND has VXLAN match rules in IPv4 ACLs "
        "applied to ingress interfaces, which could cause subsequent rules to ignore IP protocol fields. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.26.4M or later for 4.26.x train\n"
        "  * 4.27.1F or later for 4.27.x train\n"
        "2. Until upgrade is complete, implement this workaround:\n"
        "  * Replace 'protocol vxlan' matches in ACLs with:\n"
        "    - protocol udp\n"
        "    - destination port 4789 (or configured VXLAN port)\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/15267-security-advisory-0073"
    )
