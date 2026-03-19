from comfy import high


@high(
    name='rule_cve202520239',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_crypto_map='show crypto map',
        show_udp='show udp | include 500'
    ),
)
def rule_cve202520239(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20239 vulnerability in Cisco IOS Software.
    The vulnerability is in the IKEv2 feature and could allow an unauthenticated, remote attacker
    to trigger a memory leak, resulting in a denial of service (DoS) condition by causing the device
    to reload unexpectedly.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    
    # Check if this is Cisco IOS Software
    if 'Cisco IOS Software' not in version_output:
        return
    
    # Check if IKE is enabled by looking for UDP ports 500 or 4500
    udp_output = commands.show_udp
    
    # If UDP ports 500 or 4500 are not open, IKE is not enabled
    ike_enabled = '500' in udp_output
    
    if not ike_enabled:
        # Device is not vulnerable if IKE is not enabled
        return
    
    # Check if IKEv2 is being used
    crypto_map_output = commands.show_crypto_map
    
    # Check for IKEv2 Profile in crypto map configuration
    ikev2_enabled = 'IKEv2 Profile:' in crypto_map_output
    
    # If IKEv2 is not enabled, device is not vulnerable
    if not ikev2_enabled:
        return
    
    # If we reach here, the device has IKEv2 enabled and is potentially vulnerable
    # The advisory does not specify fixed versions in the provided text, so we assume
    # any device with IKEv2 enabled is vulnerable unless patched
    
    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-20239. "
        "The device has IKEv2 enabled, which makes it susceptible to a memory leak DoS attack "
        "that could cause the device to reload unexpectedly. An unauthenticated, remote attacker "
        "could exploit this by sending crafted IKEv2 packets. "
        "Please upgrade to a fixed software version. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-ios-dos-DOESHWHy"
    )