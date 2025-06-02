from comfy import high


@high(
    name='rule_cve202324548',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_ip_routing='show running-config | include ip routing',
        show_vxlan_config='show running-config | section vxlan',
        show_vxlan_vni='show vxlan vni',
        show_vlan='show vlan',
        show_ip_interface='show ip interface brief'
    ),
)
def rule_cve202324548(configuration, commands, device, devices):
    """
    This rule checks for CVE-2023-24548 vulnerability in Arista EOS devices.
    The vulnerability allows malformed or truncated packets received over a VXLAN tunnel
    to cause egress ports to be unable to forward packets when certain conditions are met.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.22.x versions
        '4.22.1F', '4.22.13M',
        # 4.23.x versions
        '4.23.0', '4.23.14M',
        # 4.24.x versions
        '4.24.0', '4.24.11M',
        # 4.25.x versions
        '4.25.0F'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if IP routing is enabled
    ip_routing = commands.show_ip_routing
    routing_enabled = 'ip routing' in ip_routing

    # Check if VXLAN is configured
    vxlan_config = commands.show_vxlan_config
    vxlan_enabled = 'interface Vxlan1' in vxlan_config

    # Check if VXLAN VNIs are routable
    vxlan_vni = commands.show_vxlan_vni
    ip_interfaces = commands.show_ip_interface

    # Look for routable VNIs (either VLAN interfaces or VRF-mapped)
    has_routable_vni = False
    if vxlan_enabled:
        # Check for VLANs with IP addresses that are also mapped to VNIs
        for line in vxlan_vni.splitlines():
            if 'VNI' in line and 'VLAN' in line:
                vlan_id = line.split()[1].strip()
                # Check if this VLAN has an IP interface that's up
                if f"Vlan{vlan_id}" in ip_interfaces and 'up' in ip_interfaces:
                    has_routable_vni = True
                    break

    # Device is vulnerable if all conditions are met
    is_vulnerable = routing_enabled and vxlan_enabled and has_routable_vni

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2023-24548. "
        "The device is running a vulnerable version AND has all vulnerability conditions met:\n"
        "1. IP routing is enabled\n"
        "2. VXLAN is configured\n"
        "3. Has routable VXLAN VNIs\n"
        "This could allow malformed VXLAN packets to cause egress ports to stop forwarding.\n"
        "Recommended fixes:\n"
        "- Upgrade to one of the following fixed versions:\n"
        "  * 4.30.0F or later for 4.30.x train\n"
        "  * 4.29.0F or later for 4.29.x train\n"
        "  * 4.28.0F or later for 4.28.x train\n"
        "  * 4.27.0F or later for 4.27.x train\n"
        "  * 4.26.0F or later for 4.26.x train\n"
        "  * 4.25.1F or later for 4.25.x train\n"
        "Note: No remediation is planned for EOS versions beyond their support lifecycle (4.22, 4.23).\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/18043-security-advisory-0089"
    )
