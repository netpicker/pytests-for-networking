from comfy import high

@high(
    name='rule_cve202520340',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        show_interfaces='show interfaces MgmtEth 0/RP0/CPU0/0'
    ),
)
def rule_cve202520340(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20340 vulnerability in Cisco IOS XR Software.
    The vulnerability affects the ARP implementation and could allow an unauthenticated, adjacent
    attacker to trigger a broadcast storm, leading to a denial of service (DoS) condition.
    
    Vulnerable conditions:
    - Running vulnerable IOS XR software version (7.11 and earlier, 24.1, 24.3, 24.4)
    - Management interface is configured with an IP address and is in Up state
    """

    # Extract command outputs
    show_version_output = commands.show_version
    show_interfaces_output = commands.show_interfaces

    # Define vulnerable version patterns
    vulnerable_version_patterns = [
        # 7.11 and earlier - checking for 7.x versions
        '7.0.', '7.1.', '7.2.', '7.3.', '7.4.', '7.5.', '7.6.', '7.7.', '7.8.', '7.9.', '7.10.', '7.11.',
        # 24.1.x versions
        '24.1.',
        # 24.3.x versions
        '24.3.',
        # 24.4.x versions
        '24.4.',
    ]

    # Check if the device is running a vulnerable version
    is_vulnerable_version = any(pattern in show_version_output for pattern in vulnerable_version_patterns)

    # Check if management interface is up and has an IP address
    mgmt_interface_up = False
    mgmt_has_ip = False
    
    if 'is up' in show_interfaces_output and 'line protocol is up' in show_interfaces_output:
        mgmt_interface_up = True
    
    if 'Internet address is' in show_interfaces_output:
        mgmt_has_ip = True

    # Device is vulnerable if running vulnerable version AND management interface is up with IP
    is_vulnerable = is_vulnerable_version and mgmt_interface_up and mgmt_has_ip

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20340. "
        f"The device is running a vulnerable version of Cisco IOS XR Software "
        f"and the management interface is configured with an IP address in the Up state. "
        f"This vulnerability could allow an unauthenticated, adjacent attacker to trigger "
        f"a broadcast storm, leading to a denial of service (DoS) condition. "
        f"Please upgrade to a fixed release: 24.2.21, 25.1.2, or 25.2.1 or later. "
        f"For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-arp-storm-EjUU55yM"
    )