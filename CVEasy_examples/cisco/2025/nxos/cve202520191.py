from comfy import high

@high(
    name='rule_cve202520191',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_ipv6_snooping_policies='show ipv6 snooping policies'
    ),
)
def rule_cve202520191(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2025-20191 vulnerability in Cisco NX-OS Software.
    The vulnerability in the Switch Integrated Security Features (SISF) could allow
    an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition
    by sending a crafted DHCPv6 packet to an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if SISF is enabled by looking for policies in the output
    snooping_policies_output = commands.show_ipv6_snooping_policies
    
    # SISF is enabled if there are any policies listed in the output
    # The output will contain "Target" header if policies exist
    is_sisf_enabled = 'Target' in snooping_policies_output and 'Type' in snooping_policies_output and 'Policy' in snooping_policies_output
    
    # If SISF is not enabled, device is not vulnerable
    if not is_sisf_enabled:
        return

    # List of vulnerable versions for Nexus 3000, 7000, and 9000 Series Switches
    # Based on the advisory, we need to check against known vulnerable releases
    # Since the advisory uses the Cisco Software Checker for specific version info,
    # we'll check for version patterns that indicate vulnerability
    
    # The vulnerability affects devices running vulnerable NX-OS releases with SISF enabled
    # We'll check if the device is running a version that needs patching
    
    # Extract version number from output
    version_vulnerable = False
    
    # Common vulnerable version patterns for NX-OS
    # This is a simplified check - in production, you'd want the complete list from Cisco Software Checker
    vulnerable_patterns = [
        '7.0(3)I7',
        '9.2(',
        '9.3(',
        '10.1(',
        '10.2(',
        '10.3(',
    ]
    
    for pattern in vulnerable_patterns:
        if pattern in version_output:
            version_vulnerable = True
            break
    
    # If version is not in known vulnerable range, assume safe
    if not version_vulnerable:
        return

    # Assert that the device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-20191. "
        "The device is running a vulnerable version of NX-OS Software AND has SISF (Switch Integrated Security Features) enabled. "
        "An unauthenticated, adjacent attacker could exploit this vulnerability by sending a crafted DHCPv6 packet, "
        "causing the device to reload and resulting in a denial of service condition. "
        "Disable SISF or upgrade to a fixed software release. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sisf-dos-ZGwt4DdY"
    )