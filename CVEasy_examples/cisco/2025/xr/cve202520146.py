from comfy import high

@high(
    name='rule_cve202520146',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config',
        show_platform='show platform'
    ),
)
def rule_cve202520146(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20146: A vulnerability in the Layer 3 multicast 
    feature of Cisco IOS XR Software for Cisco ASR 9000 Series Aggregation Services 
    Routers, ASR 9902 Compact High-Performance Routers, and ASR 9903 Compact 
    High-Performance Routers could allow an unauthenticated, remote attacker to 
    cause a line card to reset, resulting in a denial of service (DoS) condition.
    
    This vulnerability affects devices with:
    - Vulnerable IOS XR version (7.9.21, 7.10.2, 7.11, 24.1, 24.2, 24.3)
    - Lightspeed or Lightspeed-Plus-based line cards
    - IPv4 ACL or QoS policy applied to an interface on the vulnerable line card
    - Layer 3 multicast or MVPN configured
    """

    show_version_output = commands.show_version
    show_running_config_output = commands.show_running_config
    show_platform_output = commands.show_platform

    # Define vulnerable software versions
    vulnerable_versions = [
        '7.9.21',
        '7.10.2',
        '7.11',
        '24.1',
        '24.2',
        '24.3'
    ]

    # Check if device is running a vulnerable version
    is_vulnerable_version = any(version in show_version_output for version in vulnerable_versions)

    # If not a vulnerable version, device is safe
    if not is_vulnerable_version:
        return

    # Define vulnerable line cards
    lightspeed_cards = [
        'A9K-16X100GE-TR',
        'A99-16X100GE-X-SE',
        'A99-32X100GE-TR'
    ]
    
    lightspeed_plus_cards = [
        'A9K-4HG-FLEX-SE',
        'A9K-4HG-FLEX-TR',
        'A9K-8HG-FLEX-SE',
        'A9K-8HG-FLEX-TR',
        'A9K-20HG-FLEX-SE',
        'A9K-20HG-FLEX-TR',
        'A99-4HG-FLEX-SE',
        'A99-4HG-FLEX-TR',
        'A99-10X400GE-X-SE',
        'A99-10X400GE-X-TR',
        'A99-32X100GE-X-SE',
        'A99-32X100GE-X-TR'
    ]
    
    vulnerable_line_cards = lightspeed_cards + lightspeed_plus_cards
    
    # Check for vulnerable line cards or ASR 9902/9903 models
    has_vulnerable_linecard = any(card in show_platform_output for card in vulnerable_line_cards)
    is_asr_9902_9903 = 'ASR-9902' in show_platform_output or 'ASR-9903' in show_platform_output
    
    if not (has_vulnerable_linecard or is_asr_9902_9903):
        return

    # Check for multicast routing configuration
    has_multicast = 'multicast-routing' in show_running_config_output

    if not has_multicast:
        return

    # Check for IPv4 ACL or QoS policy on interfaces
    has_acl_or_qos = (
        'ipv4 access-group' in show_running_config_output or
        'service-policy input' in show_running_config_output or
        'service-policy output' in show_running_config_output
    )

    # Device is vulnerable if all conditions are met
    is_vulnerable = (
        is_vulnerable_version and
        (has_vulnerable_linecard or is_asr_9902_9903) and
        has_multicast and
        has_acl_or_qos
    )

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20146. "
        "The device is running a vulnerable version of Cisco IOS XR Software with "
        "Lightspeed or Lightspeed-Plus line cards, has Layer 3 multicast configured, "
        "and has IPv4 ACL or QoS policy applied to interfaces. "
        "This could allow an unauthenticated, remote attacker to cause a line card reset "
        "resulting in a denial of service condition. "
        "Please upgrade to a fixed release (24.2.21 or 24.4+) or remove IPv4 ACL/QoS policies "
        "from affected interfaces as a mitigation. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-multicast-ERMrSvq7"
    )