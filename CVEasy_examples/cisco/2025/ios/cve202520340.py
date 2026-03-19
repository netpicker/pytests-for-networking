from comfy import high
import re


@high(
    name='rule_cve202520340',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_interfaces='show interfaces MgmtEth 0/RP0/CPU0/0'
    ),
)
def rule_cve202520340(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20340 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to how Cisco IOS XR Software processes a high, sustained rate of ARP 
    traffic hitting the management interface. An unauthenticated, adjacent attacker could exploit 
    this vulnerability by sending an excessive amount of traffic to the management interface of an 
    affected device, overwhelming its ARP processing capabilities, leading to a DoS condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Extract the version number from the output
    version_match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not version_match:
        return
    version = version_match.group(1)

    # Version prefixes that are vulnerable (all patch levels)
    vulnerable_prefixes = ['7.0.', '7.1.', '7.2.', '7.3.', '7.4.', '7.5.', '7.6.', '7.7.', '7.8.', '7.9.', '7.10.', '7.11.',
                          '24.1.', '24.3.', '24.4.']
    # Specific vulnerable versions (exact match needed)
    vulnerable_exact = ['24.2.1', '24.2.2', '24.2.11', '24.2.12', '25.1.1', '25.1.11']

    # Check if version matches any vulnerable prefix or exact version
    version_vulnerable = any(version.startswith(p) for p in vulnerable_prefixes) or version in vulnerable_exact

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # If version is vulnerable, check if management interface is configured and up
    interfaces_output = commands.show_interfaces

    # Check if management interface is up and has an IP address assigned
    mgmt_interface_up = 'is up, line protocol is up' in interfaces_output
    mgmt_interface_has_ip = 'Internet address is' in interfaces_output

    # Device is vulnerable if management interface is up and has an IP address
    is_vulnerable = mgmt_interface_up and mgmt_interface_has_ip

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20340. "
        "The device is running a vulnerable version of Cisco IOS XR Software AND has the management "
        "interface configured with an IP address in the Up state, which makes it susceptible to ARP "
        "broadcast storm DoS attacks. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-arp-storm-EjUU55yM"
    )