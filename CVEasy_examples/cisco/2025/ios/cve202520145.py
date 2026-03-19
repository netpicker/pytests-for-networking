from comfy import high


@high(
    name='rule_cve202520145',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config_ipv4='show running-config | include ipv4 access-group .* egress',
        show_running_config_ipv6='show running-config | include ipv6 access-group .* egress'
    ),
)
def rule_cve202520145(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20145 vulnerability in Cisco IOS XR Software.
    The vulnerability exists in the ACL processing in the egress direction and affects modular
    platforms where packets are received on an ingress interface on one line card and destined
    out of an egress interface on another line card where the egress ACL is configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is a vulnerable platform (8000 Series Modular or NCS 5500 Modular)
    vulnerable_platforms = [
        '8608', '8804', '8808', '8812', '8818',
        'NCS-5504', 'NCS-5508', 'NCS-5516'
    ]
    
    platform_vulnerable = any(platform in version_output for platform in vulnerable_platforms)
    
    # If platform is not vulnerable, no need to check further
    if not platform_vulnerable:
        return

    # Check for vulnerable versions
    # For 8000 Series: 24.4 and earlier (before 25.1.1)
    # For NCS 5500: 7.10 and earlier, 7.11 (before 7.11.21), 24.1, 24.2 (before 24.2.2)
    version_vulnerable = False
    
    # Check 8000 Series vulnerable versions
    if any(model in version_output for model in ['8608', '8804', '8808', '8812', '8818']):
        if 'Version 24.4' in version_output or 'Version 24.3' in version_output or \
           'Version 24.2' in version_output or 'Version 24.1' in version_output or \
           'Version 23.' in version_output or 'Version 22.' in version_output:
            version_vulnerable = True
    
    # Check NCS 5500 vulnerable versions
    if any(model in version_output for model in ['NCS-5504', 'NCS-5508', 'NCS-5516']):
        if 'Version 7.10' in version_output or 'Version 7.9' in version_output or \
           'Version 7.8' in version_output or 'Version 7.7' in version_output or \
           'Version 7.6' in version_output or 'Version 7.5' in version_output or \
           'Version 7.4' in version_output or 'Version 7.3' in version_output or \
           'Version 7.2.' in version_output or 'Version 7.1.' in version_output or \
           'Version 7.0' in version_output or 'Version 6.' in version_output or \
           'Version 24.1' in version_output or 'Version 24.4' in version_output:
            version_vulnerable = True
        elif 'Version 7.11' in version_output:
            # Check if it's before 7.11.21
            if 'Version 7.11.21' not in version_output:
                version_vulnerable = True
        elif 'Version 24.2' in version_output:
            # Check if it's before 24.2.2
            if 'Version 24.2.2' not in version_output:
                version_vulnerable = True

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if egress ACL is configured
    ipv4_acl_output = commands.show_running_config_ipv4
    ipv6_acl_output = commands.show_running_config_ipv6

    # Check if egress IPv4 or IPv6 ACL is enabled
    egress_acl_enabled = bool(ipv4_acl_output.strip()) or bool(ipv6_acl_output.strip())

    # If egress ACL is enabled on a vulnerable version and platform, the device is vulnerable
    is_vulnerable = egress_acl_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20145. "
        "The device is running a vulnerable version of Cisco IOS XR Software on a modular platform "
        "AND has egress IPv4 or IPv6 ACL configured. This vulnerability allows an unauthenticated, "
        "remote attacker to bypass a configured egress ACL when packets are received on an ingress "
        "interface on one line card and destined out of an egress interface on another line card. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-modular-ACL-u5MEPXMm"
    )