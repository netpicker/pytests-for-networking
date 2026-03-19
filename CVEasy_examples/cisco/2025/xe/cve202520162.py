from comfy import high

@high(
    name='rule_cve202520162',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_dhcp_snooping='show ip dhcp snooping',
        show_vlan='show vlan',
        show_interfaces='show interfaces | include line|Input'
    ),
)
def rule_cve202520162(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20162 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the DHCP snooping security feature could allow an unauthenticated,
    remote attacker to cause a full interface queue wedge, resulting in a DoS condition.
    
    The vulnerability is due to improper handling of DHCP request packets. It can be exploited
    with either unicast or broadcast DHCP packets on a VLAN that does not have DHCP snooping enabled.
    
    Vulnerable products:
    - 1100 Series Integrated Service Routers (ISRs)
    - Catalyst 8200 Series Edge Platforms
    - Catalyst 8300 Series Edge Platforms
    
    The device is vulnerable if:
    - Running a vulnerable release of Cisco IOS XE Software
    - DHCP snooping is enabled for at least one, but not all, VLANs configured on the device
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (affected versions not explicitly listed in advisory,
    # so we check for presence of vulnerable product series and DHCP snooping configuration)
    vulnerable_products = [
        'ISR1100',
        'C1100',
        'C8200',
        'Catalyst 8200',
        'C8300',
        'Catalyst 8300'
    ]

    # Check if the device is a vulnerable product type
    product_vulnerable = any(product in version_output for product in vulnerable_products)

    # If product is not in vulnerable list, no need to check further
    if not product_vulnerable:
        return

    # Check DHCP snooping configuration
    dhcp_snooping_output = commands.show_dhcp_snooping
    vlan_output = commands.show_vlan

    # Check if DHCP snooping is enabled globally
    if 'Switch DHCP snooping is enabled' not in dhcp_snooping_output:
        # DHCP snooping is not enabled, device is not vulnerable
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
                    if vlan_line and not vlan_line.startswith('DHCP') and not vlan_line.startswith('Proxy'):
                        # Parse VLAN numbers (can be comma-separated or ranges)
                        vlan_parts = vlan_line.replace(' ', '').split(',')
                        for part in vlan_parts:
                            if '-' in part:
                                start, end = part.split('-')
                                snooping_vlans.update(range(int(start), int(end) + 1))
                            elif part.isdigit():
                                snooping_vlans.add(int(part))
                break

    # Extract all active VLANs
    all_vlans = set()
    if vlan_output:
        lines = vlan_output.split('\n')
        for line in lines:
            parts = line.split()
            if parts and parts[0].isdigit():
                all_vlans.add(int(parts[0]))

    # Check if DHCP snooping is enabled for some but not all VLANs
    if snooping_vlans and all_vlans:
        if snooping_vlans != all_vlans and len(snooping_vlans) > 0:
            # DHCP snooping is enabled for some but not all VLANs - vulnerable configuration
            
            # Check for indicators of compromise (queue wedge)
            interfaces_output = commands.show_interfaces
            queue_wedged = False
            if interfaces_output:
                lines = interfaces_output.split('\n')
                for line in lines:
                    if 'Input queue:' in line:
                        # Parse input queue: size/max/drops/flushes
                        parts = line.split('Input queue:')
                        if len(parts) > 1:
                            queue_info = parts[1].strip().split('/')[0:2]
                            if len(queue_info) == 2:
                                try:
                                    size = int(queue_info[0].strip())
                                    max_val = int(queue_info[1].strip())
                                    if size > max_val:
                                        queue_wedged = True
                                        break
                                except ValueError:
                                    pass

            vulnerability_msg = (
                f"Device {device.name} is vulnerable to CVE-2025-20162. "
                f"The device is running a vulnerable product series with DHCP snooping enabled "
                f"for some VLANs ({snooping_vlans}) but not all VLANs ({all_vlans}). "
            )
            
            if queue_wedged:
                vulnerability_msg += "CRITICAL: Input queue wedge detected - device may be under active exploitation! "
            
            vulnerability_msg += (
                "Workaround: Enable DHCP snooping on all VLANs using 'ip dhcp snooping vlan <vlan-range>'. "
                "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-dhcpsn-dos-xBn8Mtks"
            )
            
            assert False, vulnerability_msg

    # If we reach here, device is not vulnerable
    return