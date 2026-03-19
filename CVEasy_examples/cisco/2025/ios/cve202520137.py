from comfy import high


@high(
    name='rule_cve202520137',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config',
        show_dhcp_snooping='show ip dhcp snooping'
    ),
)
def rule_cve202520137(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20137 vulnerability in Cisco Catalyst 1000 and 2960L Switches.
    The vulnerability is due to the use of both an IPv4 ACL and a dynamic ACL of IP Source Guard on the same interface,
    which is an unsupported configuration that allows an unauthenticated, remote attacker to bypass a configured ACL.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if the device is a Catalyst 1000 or 2960L Switch
    is_catalyst_1000 = 'C1000' in version_output or 'Catalyst 1000' in version_output
    is_catalyst_2960l = 'C2960L' in version_output or 'Catalyst 2960L' in version_output or '2960-L' in version_output

    # If not a vulnerable platform, no need to check further
    if not (is_catalyst_1000 or is_catalyst_2960l):
        return

    # Extract configuration output
    config_output = commands.show_running_config
    dhcp_snooping_output = commands.show_dhcp_snooping

    # Parse the configuration to find interfaces with both IPv4 ACL and IP Source Guard
    vulnerable_interfaces = []
    
    # Split configuration into lines
    config_lines = config_output.split('\n')
    
    current_interface = None
    has_acl = False
    has_ip_verify_source = False
    interface_vlan = None
    
    for line in config_lines:
        line = line.strip()
        
        # Check for interface definition
        if line.startswith('interface '):
            # Save previous interface if it was vulnerable
            if current_interface and has_acl and has_ip_verify_source:
                # Check if DHCP snooping is enabled for the VLAN
                if interface_vlan and f'DHCP snooping is configured on following VLANs' in dhcp_snooping_output:
                    # Extract configured VLANs from DHCP snooping output
                    dhcp_lines = dhcp_snooping_output.split('\n')
                    for i, dhcp_line in enumerate(dhcp_lines):
                        if 'DHCP snooping is configured on following VLANs' in dhcp_line:
                            if i + 1 < len(dhcp_lines):
                                configured_vlans = dhcp_lines[i + 1].strip()
                                if interface_vlan in configured_vlans or interface_vlan.replace('vlan ', '') in configured_vlans:
                                    vulnerable_interfaces.append(current_interface)
                                    break
                elif not interface_vlan:
                    # If no VLAN specified, still consider it vulnerable if both features are configured
                    vulnerable_interfaces.append(current_interface)
            
            # Reset for new interface
            current_interface = line.replace('interface ', '')
            has_acl = False
            has_ip_verify_source = False
            interface_vlan = None
        
        # Check for IPv4 ACL (ip access-group)
        elif 'ip access-group' in line and current_interface:
            has_acl = True
        
        # Check for IP Source Guard (ip verify source)
        elif 'ip verify source' in line and current_interface:
            has_ip_verify_source = True
        
        # Check for VLAN assignment
        elif 'switchport access vlan' in line and current_interface:
            interface_vlan = line.split()[-1]
    
    # Check last interface
    if current_interface and has_acl and has_ip_verify_source:
        if interface_vlan and f'DHCP snooping is configured on following VLANs' in dhcp_snooping_output:
            dhcp_lines = dhcp_snooping_output.split('\n')
            for i, dhcp_line in enumerate(dhcp_lines):
                if 'DHCP snooping is configured on following VLANs' in dhcp_line:
                    if i + 1 < len(dhcp_lines):
                        configured_vlans = dhcp_lines[i + 1].strip()
                        if interface_vlan in configured_vlans or interface_vlan.replace('vlan ', '') in configured_vlans:
                            vulnerable_interfaces.append(current_interface)
                            break
        elif not interface_vlan:
            vulnerable_interfaces.append(current_interface)

    # Assert that no vulnerable interfaces exist
    assert not vulnerable_interfaces, (
        f"Device {device.name} is vulnerable to CVE-2025-20137. "
        f"The following interface(s) have both IPv4 ACL and IP Source Guard configured, which is an unsupported configuration: {', '.join(vulnerable_interfaces)}. "
        "This allows an attacker to bypass the configured ACL. "
        "Workaround: Configure only one ACL type (either IPv4 ACL or IP Source Guard) on each interface. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipsgacl-pg6qfZk"
    )