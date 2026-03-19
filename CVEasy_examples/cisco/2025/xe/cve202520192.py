from comfy import high

@high(
    name='rule_cve202520192',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_udp='show udp | include 500',
        show_crypto_map='show crypto map'
    ),
)
def rule_cve202520192(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20192 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the Internet Key Exchange version 1 (IKEv1) implementation could allow
    an authenticated, remote attacker to cause a denial of service (DoS) condition by sending
    crafted IKEv1 messages to the affected device.
    
    The vulnerability is due to improper validation of IKEv1 phase 2 parameters before the
    IPsec security association creation request is handed off to the hardware cryptographic
    accelerator of an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    
    # List of vulnerable product families
    vulnerable_products = [
        '1000 Series Integrated Services Router',
        '4000 Series Integrated Services Router',
        'Catalyst 8200',
        'Catalyst 8300',
        'Catalyst 8500',
        'Catalyst 8500L'
    ]
    
    # Check if the device is a vulnerable product type
    product_vulnerable = any(product in version_output for product in vulnerable_products)
    
    # If product is not in the vulnerable list, device is not affected
    if not product_vulnerable:
        return
    
    # Check if IKE is enabled (UDP ports 500 or 4500 are open)
    udp_output = commands.show_udp
    ike_enabled = ('500' in udp_output and len(udp_output.strip()) > 0)
    
    # If IKE is not enabled, device is not vulnerable
    if not ike_enabled:
        return
    
    # Check if IKEv1 is being used (crypto map without IKEv2 Profile)
    crypto_map_output = commands.show_crypto_map
    
    # If no crypto map is configured, device is not vulnerable
    if not crypto_map_output or 'Crypto Map' not in crypto_map_output:
        return
    
    # Check if IKEv1 is being used (no IKEv2 Profile listed in crypto map)
    ikev1_in_use = ('ipsec-isakmp' in crypto_map_output and 
                    'IKEv2 Profile:' not in crypto_map_output and
                    'Interfaces using crypto map' in crypto_map_output)
    
    # If IKEv1 is in use, the device is vulnerable
    assert not ikev1_in_use, (
        f"Device {device.name} is vulnerable to CVE-2025-20192. "
        "The device is running a vulnerable Cisco IOS XE platform with IKEv1 enabled. "
        "An authenticated attacker with valid IKEv1 VPN credentials could cause a denial of service "
        "by sending crafted IKEv1 messages. Upgrade to a fixed software version or migrate to IKEv2. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ikev1-dos-XHk3HzFC"
    )