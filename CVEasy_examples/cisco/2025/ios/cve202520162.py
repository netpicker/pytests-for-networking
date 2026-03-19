from comfy import high


@high(
    name='rule_cve202520162',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_dhcp_snooping='show ip dhcp snooping',
        show_vlan='show vlan'
    ),
)
def rule_cve202520162(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20162 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper handling of DHCP request packets when DHCP snooping is
    enabled on some but not all VLANs, which can be exploited by an unauthenticated, remote
    attacker to cause a denial of service (DoS) condition by wedging the interface queue.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE (vulnerability only affects IOS XE, not IOS)
    if 'IOS XE' not in version_output:
        return

    # Extract DHCP snooping configuration
    dhcp_snooping_output = commands.show_dhcp_snooping

    # Check if DHCP snooping is enabled globally
    dhcp_snooping_enabled = 'DHCP snooping is enabled' in dhcp_snooping_output

    # If DHCP snooping is not enabled at all, device is not vulnerable
    if not dhcp_snooping_enabled:
        return

    # Extract VLANs with DHCP snooping enabled
    snooping_vlans = set()
    if 'DHCP snooping is configured on following VLANs:' in dhcp_snooping_output:
        lines = dhcp_snooping_output.split('\n')
        for i, line in enumerate(lines):
            if 'DHCP snooping is configured on following VLANs:' in line:
                # Next line should contain the VLAN numbers
                if i + 1 < len(lines):
                    vlan_line = lines[i + 1].strip()
                    if vlan_line and not vlan_line.startswith('DHCP'):
                        # Parse VLAN numbers (can be comma-separated or ranges)
                        vlan_parts = vlan_line.replace(',', ' ').split()
                        for part in vlan_parts:
                            if '-' in part:
                                start, end = part.split('-')
                                snooping_vlans.update(range(int(start), int(end) + 1))
                            elif part.isdigit():
                                snooping_vlans.add(int(part))
                break

    # Extract all active VLANs
    vlan_output = commands.show_vlan
    all_vlans = set()
    
    if vlan_output:
        lines = vlan_output.split('\n')
        for line in lines:
            # Parse VLAN lines (format: "VLAN_ID Name Status Ports")
            parts = line.split()
            if parts and parts[0].isdigit():
                vlan_id = int(parts[0])
                # Exclude reserved VLANs (1002-1005)
                if vlan_id not in [1002, 1003, 1004, 1005]:
                    all_vlans.add(vlan_id)

    # Device is vulnerable if DHCP snooping is enabled on some but not all VLANs
    is_vulnerable = False
    if snooping_vlans and all_vlans:
        # If there are VLANs without DHCP snooping, device is vulnerable
        vlans_without_snooping = all_vlans - snooping_vlans
        is_vulnerable = len(vlans_without_snooping) > 0

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20162. "
        "The device is running Cisco IOS XE Software with DHCP snooping enabled on some but not all VLANs, "
        "which makes it susceptible to DoS attacks via malformed DHCP packets causing interface queue wedges. "
        f"VLANs with DHCP snooping: {sorted(snooping_vlans)}, "
        f"VLANs without DHCP snooping: {sorted(vlans_without_snooping)}. "
        "Workaround: Enable DHCP snooping on all VLANs. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-dhcpsn-dos-xBn8Mtks"
    )