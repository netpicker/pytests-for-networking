import re
from comfy import high

@high(
    name='rule_cve202521595',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_evpn_config='show configuration | display set | match "protocols evpn"',
        show_vxlan_config='show configuration | display set | match "vxlan"',
        show_chassis_fpc='show chassis fpc'
    ),
)
def rule_cve202521595(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-21595 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an adjacent, unauthenticated attacker to cause FPC crashes through
    memory leaks when specific ARP/NDP packets are received in EVPN-VXLAN scenarios.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions for Junos OS
    vulnerable_versions = [
        # All versions before 21.2R3-S7
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6',
        # 21.4 versions before 21.4R3-S4
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        # 22.2 versions before 22.2R3-S1
        '22.2R1', '22.2R2', '22.2R3',
        # 22.3 versions before 22.3R3-S1
        '22.3R1', '22.3R2', '22.3R3',
        # 22.4 versions before 22.4R2-S2, 22.4R3
        '22.4R1', '22.4R2', '22.4R2-S1',
        # Junos OS Evolved versions
        '21.2R1-EVO', '21.2R2-EVO', '21.2R3-EVO', '21.2R3-S1-EVO', '21.2R3-S2-EVO', '21.2R3-S3-EVO', '21.2R3-S4-EVO', '21.2R3-S5-EVO', '21.2R3-S6-EVO',
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO', '21.4R3-S1-EVO', '21.4R3-S2-EVO', '21.4R3-S3-EVO',
        '22.2R1-EVO', '22.2R2-EVO', '22.2R3-EVO',
        '22.3R1-EVO', '22.3R2-EVO', '22.3R3-EVO',
        '22.4R1-EVO', '22.4R2-EVO', '22.4R2-S1-EVO'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is MX Series (which is NOT affected)
    chassis_output = commands.show_chassis_hardware
    is_mx_platform = 'MX' in chassis_output

    if is_mx_platform:
        return

    # Check for EVPN-VXLAN configuration
    evpn_output = commands.show_evpn_config
    vxlan_output = commands.show_vxlan_config
    
    has_evpn = 'protocols evpn' in evpn_output
    has_vxlan = 'vxlan' in vxlan_output

    # Check for heap memory growth in FPC
    fpc_output = commands.show_chassis_fpc
    has_heap_growth = False
    
    for line in fpc_output.splitlines():
        if 'Online' in line:
            parts = line.split()
            # Check if heap utilization is present and greater than 15%
            if len(parts) >= 10:
                try:
                    heap_util = int(parts[9])
                    if heap_util > 15:
                        has_heap_growth = True
                        break
                except (ValueError, IndexError):
                    pass

    # Device is vulnerable if running vulnerable version with EVPN-VXLAN configuration
    is_vulnerable = has_evpn and has_vxlan

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-21595. "
        "The device is running a vulnerable version of Junos OS with EVPN-VXLAN configuration, "
        "which makes it susceptible to FPC crashes due to memory leaks when specific ARP/NDP packets are received. "
        f"Heap memory growth detected: {has_heap_growth}. "
        "For more information, see https://supportportal.juniper.net/JSA88139"
    )