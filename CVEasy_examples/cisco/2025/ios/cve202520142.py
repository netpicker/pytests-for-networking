from comfy import high


@high(
    name='rule_cve202520142',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_platform='show platform',
        show_running_config='show running-config'
    ),
)
def rule_cve202520142(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20142 vulnerability in Cisco ASR 9000 Series Routers.
    The vulnerability is due to incorrect handling of malformed IPv4 packets on line cards where an IPv4 ACL
    or QoS policy is applied, which can be exploited by an unauthenticated, remote attacker to cause a
    denial of service (DoS) condition by resetting the line card.
    """
    # Extract the version and platform information from the command output
    version_output = commands.show_version
    platform_output = commands.show_platform
    config_output = commands.show_running_config

    # Check if device is an affected platform (ASR 9000 Series, ASR 9902, ASR 9903)
    # Platform output may show 'A9K' or 'A99' prefixes for line cards
    affected_platforms = ['ASR 9000', 'ASR 9902', 'ASR 9903', 'ASR9K', 'A9K', 'A99', 'ASR-9000', 'ASR-9902', 'ASR-9903']
    platform_affected = any(platform.lower() in version_output.lower() or platform.lower() in platform_output.lower() 
                           for platform in affected_platforms)

    # If platform is not affected, no need to check further
    if not platform_affected:
        return

    # Check if device has Lightspeed or Lightspeed-Plus line cards
    lightspeed_cards = [
        'A9K-16X100GE-TR', 'A99-16X100GE-X-SE', 'A99-32X100GE-TR',
        'A9K-4HG-FLEX-SE', 'A9K-4HG-FLEX-TR', 'A9K-8HG-FLEX-SE', 'A9K-8HG-FLEX-TR',
        'A9K-20HG-FLEX-SE', 'A9K-20HG-FLEX-TR', 'A99-4HG-FLEX-SE', 'A99-4HG-FLEX-TR',
        'A99-10X400GE-X-SE', 'A99-10X400GE-X-TR', 'A99-32X100GE-X-SE', 'A99-32X100GE-X-TR'
    ]
    
    has_vulnerable_linecard = any(card in platform_output for card in lightspeed_cards)
    
    # ASR 9902 and 9903 have integrated Lightspeed-Plus cards
    if 'ASR 9902' in version_output or 'ASR 9903' in version_output or 'ASR 9902' in platform_output or 'ASR 9903' in platform_output:
        has_vulnerable_linecard = True

    # If no vulnerable line cards, device is not affected
    if not has_vulnerable_linecard:
        return

    # List of vulnerable software versions (use more specific patterns to avoid substring matches)
    vulnerable_version_patterns = [
        'Version 7.0.', 'Version 7.1.', 'Version 7.2.', 'Version 7.3.', 'Version 7.4.', 
        'Version 7.5.', 'Version 7.6.', 'Version 7.7.', 'Version 7.8.',
        'Version 7.9.1\n', 'Version 7.9.2\n', 'Version 7.9.3\n', 'Version 7.9.4\n', 
        'Version 7.9.5\n', 'Version 7.9.6\n', 'Version 7.9.7\n', 'Version 7.9.8\n', 'Version 7.9.9\n',
        'Version 7.9.10', 'Version 7.9.11', 'Version 7.9.12', 'Version 7.9.13', 'Version 7.9.14', 
        'Version 7.9.15', 'Version 7.9.16', 'Version 7.9.17', 'Version 7.9.18', 'Version 7.9.19', 'Version 7.9.20',
        'Version 7.10.1\n', 'Version 6.'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if IPv4 ACL or QoS policy is applied to any interface
    has_ipv4_acl = 'ipv4 access-group' in config_output
    has_qos_policy = 'service-policy' in config_output

    # If either IPv4 ACL or QoS policy is configured, the device is vulnerable
    is_vulnerable = has_ipv4_acl or has_qos_policy

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20142. "
        "The device is running a vulnerable IOS XR version on an ASR 9000 series router with Lightspeed/Lightspeed-Plus line cards "
        "AND has IPv4 ACL or QoS policy applied to an interface, which makes it susceptible to DoS attacks via malformed IPv4 packets. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv4uni-LfM3cfBu"
    )