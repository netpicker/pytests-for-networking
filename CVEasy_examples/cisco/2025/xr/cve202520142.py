from comfy import high

@high(
    name='rule_cve202520142',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config',
        show_platform='show platform'
    ),
)
def rule_cve202520142(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20142 vulnerability in Cisco IOS XR Software
    for ASR 9000 Series Routers. The vulnerability affects devices with Lightspeed or 
    Lightspeed-Plus line cards when IPv4 ACL or QoS policies are applied to interfaces.
    
    An unauthenticated, remote attacker could exploit this by sending crafted IPv4 packets
    to cause a line card reset, resulting in a denial of service condition.
    """

    # Extract command outputs
    show_version_output = commands.show_version
    show_running_config_output = commands.show_running_config
    show_platform_output = commands.show_platform

    # Define vulnerable software versions (7.8 and earlier, 7.9.x before 7.9.21, 7.10.x before 7.10.2)
    # Use more specific patterns to avoid substring matches (e.g., '7.9.1' matching '7.9.10')
    vulnerable_version_patterns = [
        'Version 7.0.', 'Version 7.1.', 'Version 7.2.', 'Version 7.3.', 'Version 7.4.', 
        'Version 7.5.', 'Version 7.6.', 'Version 7.7.', 'Version 7.8.',
        'Version 7.9.1\n', 'Version 7.9.2\n', 'Version 7.9.3\n', 'Version 7.9.4\n', 
        'Version 7.9.5\n', 'Version 7.9.6\n', 'Version 7.9.7\n', 'Version 7.9.8\n', 'Version 7.9.9\n',
        'Version 7.9.10', 'Version 7.9.11', 'Version 7.9.12', 'Version 7.9.13', 'Version 7.9.14', 
        'Version 7.9.15', 'Version 7.9.16', 'Version 7.9.17', 'Version 7.9.18', 'Version 7.9.19', 'Version 7.9.20',
        'Version 7.10.1\n'
    ]

    # Check if device is running a vulnerable version
    is_vulnerable_version = any(version in show_version_output for version in vulnerable_version_patterns)

    # Check if device is an affected platform (ASR 9000, 9902, 9903)
    # Platform output may show 'A9K' or 'A99' prefixes for line cards
    is_affected_platform = any(platform in show_platform_output.lower() or platform in show_version_output.lower() for platform in [
        'asr 9000', 'asr9000', 'asr 9902', 'asr9902', 'asr 9903', 'asr9903', 'a9k', 'a99'
    ])

    # Check for Lightspeed or Lightspeed-Plus line cards
    lightspeed_cards = [
        'A9K-16X100GE-TR', 'A99-16X100GE-X-SE', 'A99-32X100GE-TR',
        'A9K-4HG-FLEX-SE', 'A9K-4HG-FLEX-TR', 'A9K-8HG-FLEX-SE', 'A9K-8HG-FLEX-TR',
        'A9K-20HG-FLEX-SE', 'A9K-20HG-FLEX-TR', 'A99-4HG-FLEX-SE', 'A99-4HG-FLEX-TR',
        'A99-10X400GE-X-SE', 'A99-10X400GE-X-TR', 'A99-32X100GE-X-SE', 'A99-32X100GE-X-TR'
    ]
    
    has_lightspeed_card = any(card in show_platform_output for card in lightspeed_cards)

    # Check for vulnerable configuration (IPv4 ACL or QoS policy applied to interface)
    has_ipv4_acl = 'ipv4 access-group' in show_running_config_output
    has_qos_policy = 'service-policy' in show_running_config_output
    
    has_vulnerable_config = has_ipv4_acl or has_qos_policy

    # Device is vulnerable if all conditions are met
    is_vulnerable = (
        is_vulnerable_version and 
        is_affected_platform and 
        has_lightspeed_card and 
        has_vulnerable_config
    )

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20142. "
        f"The device is running a vulnerable version of Cisco IOS XR Software "
        f"on an ASR 9000 series platform with Lightspeed/Lightspeed-Plus line cards "
        f"and has IPv4 ACL or QoS policy configured on interfaces. "
        f"This could allow an unauthenticated, remote attacker to cause a line card reset "
        f"by sending crafted IPv4 packets, resulting in a denial of service condition. "
        f"Please upgrade to a fixed release (7.9.21, 7.10.2, or 7.11+) or remove "
        f"IPv4 ACL/QoS policies from affected interfaces. "
        f"For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv4uni-LfM3cfBu"
    )