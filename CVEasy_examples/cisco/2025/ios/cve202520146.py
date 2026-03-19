from comfy import high


@high(
    name='rule_cve202520146',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_platform='show platform',
        show_running_config_multicast='show running-config multicast-routing',
        show_running_config_interfaces='show running-config | section interface'
    ),
)
def rule_cve202520146(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20146 vulnerability in Cisco IOS XR Software
    for ASR 9000 Series Routers. The vulnerability is due to incorrect handling of malformed IPv4
    multicast packets on line cards with IPv4 ACL or QoS policy applied, which can cause a line card
    reset resulting in a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    platform_output = commands.show_platform

    # Check if device is an affected platform (ASR 9000 Series, ASR 9902, ASR 9903)
    affected_platforms = ['ASR 9000', 'ASR9000', 'ASR 9902', 'ASR9902', 'ASR 9903', 'ASR9903']
    is_affected_platform = any(platform in version_output or platform in platform_output 
                               for platform in affected_platforms)

    # If not an affected platform, device is not vulnerable
    if not is_affected_platform:
        return

    # Check for Lightspeed or Lightspeed-Plus line cards
    lightspeed_cards = [
        'A9K-16X100GE-TR', 'A99-16X100GE-X-SE', 'A99-32X100GE-TR',
        'A9K-4HG-FLEX-SE', 'A9K-4HG-FLEX-TR', 'A9K-8HG-FLEX-SE', 'A9K-8HG-FLEX-TR',
        'A9K-20HG-FLEX-SE', 'A9K-20HG-FLEX-TR', 'A99-4HG-FLEX-SE', 'A99-4HG-FLEX-TR',
        'A99-10X400GE-X-SE', 'A99-10X400GE-X-TR', 'A99-32X100GE-X-SE', 'A99-32X100GE-X-TR'
    ]
    
    has_lightspeed_card = any(card in platform_output for card in lightspeed_cards)
    
    # ASR 9902 and 9903 have integrated Lightspeed-Plus cards
    if 'ASR 9902' in version_output or 'ASR9902' in version_output or \
       'ASR 9903' in version_output or 'ASR9903' in version_output:
        has_lightspeed_card = True

    # If no Lightspeed cards, device is not vulnerable
    if not has_lightspeed_card:
        return

    # List of vulnerable software versions (7.9.21, 7.10.2, 7.11, 24.1, 24.2, 24.3)
    vulnerable_version_patterns = [
        '7.9.21', '7.10.2', '7.11', '24.1', '24.2', '24.3'
    ]

    # Check if the current device's software version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_version_patterns)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if multicast routing is configured
    multicast_config = commands.show_running_config_multicast
    multicast_enabled = 'multicast-routing' in multicast_config or 'address-family ipv4' in multicast_config

    # If multicast is not enabled, device is not vulnerable
    if not multicast_enabled:
        return

    # Check if any interface has IPv4 ACL or QoS policy applied
    interface_config = commands.show_running_config_interfaces
    
    has_acl = 'ipv4 access-group' in interface_config
    has_qos = 'service-policy' in interface_config

    # Device is vulnerable if it has ACL or QoS policy on interfaces
    is_vulnerable = has_acl or has_qos

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20146. "
        "The device is running a vulnerable IOS XR version on an ASR 9000 Series router with Lightspeed/Lightspeed-Plus line cards, "
        "has Layer 3 multicast enabled, AND has IPv4 ACL or QoS policy applied to interfaces, "
        "which makes it susceptible to DoS attacks via malformed IPv4 multicast packets. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-multicast-ERMrSvq7"
    )