from comfy import high


@high(
    name='rule_cve202520192',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_udp='show udp | include 500',
        show_crypto_map='show crypto map'
    ),
)
def rule_cve202520192(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20192 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper validation of IKEv1 phase 2 parameters before the IPsec
    security association creation request is handed off to the hardware cryptographic accelerator.
    An authenticated, remote attacker with valid IKEv1 VPN credentials could exploit this vulnerability
    by sending crafted IKEv1 messages to cause the device to reload.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE Software
    is_ios_xe = 'IOS XE Software' in version_output or 'Cisco IOS XE Software' in version_output

    # Check if device is one of the vulnerable platforms
    vulnerable_platforms = [
        '1000 Series',
        'ISR1',
        'ISR4',
        '4000 Series',
        'Catalyst 8200',
        'Catalyst 8300',
        'Catalyst 8500',
        'C8200',
        'C8300',
        'C8500'
    ]

    platform_vulnerable = any(platform in version_output for platform in vulnerable_platforms)

    # If not IOS XE or not a vulnerable platform, device is not affected
    if not is_ios_xe or not platform_vulnerable:
        return

    # Check if IKE is enabled (UDP ports 500 or 4500 are open)
    udp_output = commands.show_udp
    ike_enabled = '500' in udp_output or '4500' in udp_output

    # If IKE is not enabled, device is not vulnerable
    if not ike_enabled:
        return

    # Check if IKEv1 is being used (crypto map without IKEv2 Profile)
    crypto_map_output = commands.show_crypto_map

    # Device is vulnerable if:
    # 1. Crypto map exists
    # 2. Crypto map does NOT have "IKEv2 Profile" (which means it's using IKEv1)
    # 3. Crypto map has interfaces using it
    has_crypto_map = 'Crypto Map' in crypto_map_output
    has_ikev2_profile = 'IKEv2 Profile:' in crypto_map_output
    has_active_interface = 'Interfaces using crypto map' in crypto_map_output

    # If there's a crypto map that's active and doesn't use IKEv2, it's using IKEv1
    is_vulnerable = has_crypto_map and not has_ikev2_profile and has_active_interface

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20192. "
        "The device is running Cisco IOS XE Software on a vulnerable platform with IKEv1 enabled. "
        "An authenticated attacker with valid IKEv1 VPN credentials could send crafted IKEv1 messages "
        "to cause a denial of service condition by reloading the device. "
        "Upgrade to a fixed software version or migrate to IKEv2. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ikev1-dos-XHk3HzFC"
    )