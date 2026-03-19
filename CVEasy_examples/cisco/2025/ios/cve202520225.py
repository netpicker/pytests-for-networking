from comfy import high


@high(
    name='rule_cve202520225',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_udp='show udp | include 500',
        show_crypto_map='show crypto map'
    ),
)
def rule_cve202520225(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20225 vulnerability in Cisco IOS Software.
    The vulnerability is in the IKEv2 feature and could allow an unauthenticated, remote attacker
    to trigger a memory leak, resulting in a denial of service (DoS) condition causing device reload.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    
    # Check if this is a vulnerable IOS version
    # Based on advisory, this affects IOS Software with IKEv2 enabled
    # We'll check if it's IOS (not IOS XE, XR, NX-OS)
    is_ios = 'Cisco IOS Software' in version_output and 'IOS-XE' not in version_output
    
    if not is_ios:
        return
    
    # Check if IKE is enabled by looking for UDP ports 500 or 4500
    udp_output = commands.show_udp
    ike_enabled = ('500' in udp_output) if udp_output else False
    
    # If IKE is not enabled, device is not vulnerable
    if not ike_enabled:
        return
    
    # Check if IKEv2 is being used by looking for IKEv2 Profile in crypto map
    crypto_map_output = commands.show_crypto_map
    ikev2_enabled = 'IKEv2 Profile:' in crypto_map_output if crypto_map_output else False
    
    # Device is vulnerable if IKEv2 is enabled
    is_vulnerable = ikev2_enabled
    
    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20225. "
        "The device is running Cisco IOS Software with IKEv2 enabled, "
        "which makes it susceptible to memory leak DoS attacks that can cause device reload. "
        "An unauthenticated, remote attacker can exploit this by sending crafted IKEv2 packets. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-ios-dos-DOESHWHy"
    )